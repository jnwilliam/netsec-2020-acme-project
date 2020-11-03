import argparse
import sys
import os
import requests
from http import server
import threading
import socketserver
import http
from dnslib import *
import time
import json
import ssl
import base64
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

DNS_PORT = 10053
CHALLENGE_SERVER_PORT = 5002
CERTIFICATE_SERVER_PORT = 5001
SHUTDOWN_SERVER_PORT = 5003
ACME_SERVER_CERTIFICATE_LOCATION = os.path.join(os.getcwd(), "pebble.minica.pem")

DNS_TTL = 60 * 60

dns_record_ip_address = "0.0.0.0"
challenge_type = "dns01"
acme_directory_url = "example_acme.com/dir"
domains = ["example.com"]
revoke = False
shutdown = False
public_key = None
private_key = None

http_key_auth = ""
http_token = ""


class DnsRecords:
    def __init__(
            self,
            qtype: QTYPE,
            hostname: string,
            rdata: string):
        self.qtype = qtype
        self.hostname = hostname
        self.rdata = rdata


dns_records = []


def rsa_encrypt(key: rsa.RSAPublicKey, message: bytes):
    return key.encrypt(message, padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None))


def rsa_decrypt(key: rsa.RSAPrivateKey, message: bytes):
    return key.decrypt(message, padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None))


def acme_base64_encoding(data):
    if isinstance(data, str):
        data = data.encode("utf8")
    encoded_data = base64.urlsafe_b64encode(data).rstrip(b'=')
    return encoded_data.decode("utf8")


class AcmeClient:
    def __init__(self, directory_url: string, jws_algorith: string="ES256"):
        r = requests.get(directory_url, verify=ACME_SERVER_CERTIFICATE_LOCATION)
        self.resources = r.json()
        self.nonce = None
        self.jws_algorithm = jws_algorith
        self.jwk_private_key = None
        self.jwk_public_key = None
        self.account_url = None
        self.get_new_nonce()
        self.create_jwk()
        self.order = None

    def create_jwk(self):
        if self.jws_algorithm == "ES256":
            if self.jwk_private_key is None:
                self.jwk_private_key = ec.generate_private_key(ec.SECP256R1())
            x = acme_base64_encoding(self.jwk_private_key.public_key().public_numbers().x.to_bytes(32, "big"))
            y = acme_base64_encoding(self.jwk_private_key.public_key().public_numbers().y.to_bytes(32, "big"))
            self.jwk_public_key = {"kty": "EC",
                                   "crv": "P-256",
                                   "x": x,
                                   "y": y}
        else:
            raise RuntimeError("Unknown algorithm: " + self.jws_algorithm)

    def create_jws_object(self, url: string, payload, use_jwk: bool = False):
        if not use_jwk and not self.account_url:
            raise RuntimeError("Can't use kid, since you aren't logged in!")
        header = {"alg": self.jws_algorithm,
                  "nonce": self.nonce,
                  "url": url}
        if use_jwk:
            header["jwk"] = self.jwk_public_key
        else:
            header["kid"] = self.account_url
        header_base64url = acme_base64_encoding(json.dumps(header))
        payload_base64url = ""
        if payload:
            payload_base64url = acme_base64_encoding(json.dumps(payload))
        signature_content = header_base64url + '.' + payload_base64url
        r, s = decode_dss_signature(self.jwk_private_key.sign(signature_content.encode("utf8"),
                                                              ec.ECDSA(hashes.SHA256())))
        signature = acme_base64_encoding(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        print("Request: " + json.dumps({"url": header["url"], "payload": payload}))
        return json.dumps({"protected": header_base64url,
                           "payload": payload_base64url,
                           "signature": signature})

    def create_signed_acme_request(self, url: string, payload, use_jwk: bool = False, return_header: bool = False):
        request = self.create_jws_object(url=url, payload=payload, use_jwk=use_jwk)
        r = requests.post(url=url,
                          data=request,
                          verify=ACME_SERVER_CERTIFICATE_LOCATION,
                          headers={"Content-Type": "application/jose+json"})
        try:
            self.nonce = r.headers["Replay-Nonce"]
        except KeyError:
            self.nonce = None
        r_json = r.json()
        r_headers = r.headers
        print("    Headers: " + str(r_headers))
        print("    Body: " + str(r_json))
        print()
        if r.status_code == 400 and r_json["type"] == "urn:ietf:params:acme:error:badNonce":
            print("Status code:", r.status_code, "- Retry (" + json.dumps(r_json) + ")")
            r_json, r_headers = self.create_signed_acme_request(url=url,
                                                                payload=payload,
                                                                use_jwk=use_jwk,
                                                                return_header=True)
        if return_header:
            return r_json, r_headers
        else:
            return r_json

    def get_new_nonce(self):
        r = requests.head(self.resources["newNonce"], verify=ACME_SERVER_CERTIFICATE_LOCATION)
        self.nonce = r.headers["Replay-Nonce"]
        print("Requested new nonce from server: " + self.nonce)

    def create_account(self):
        r = self.create_signed_acme_request(self.resources["newAccount"],
                                            payload={"termsOfServiceAgreed": True},
                                            use_jwk=True,
                                            return_header=True)
        self.account_url = r[1]["Location"]

    def create_order(self):
        payload = {"identifiers": []}
        for domain in domains:
            payload["identifiers"].append({"type": "dns", "value": domain})
        r = self.create_signed_acme_request(self.resources["newOrder"],
                                            payload=payload)
        self.order = r
        #print(r)

    def get_challenges(self):
        challenges = []
        for auth in self.order["authorizations"]:
            challenge = self.create_signed_acme_request(auth, {})
            try:
                wildcard = challenge["wildcard"]
            except KeyError:
                wildcard = False
            challenges.append({"domain": challenge["identifier"]["value"],
                               "wildcard": wildcard,
                               "challenges": challenge["challenges"]})
        return challenges

    def get_challenges_from_type(self, challenge_type_name: string = "dns01"):
        if challenge_type_name in ["dns01", "dns-01"]:
            challenge_type_name = "dns-01"
        elif challenge_type_name in ["http01", "http-01"]:
            challenge_type_name = "http-01"
        else:
            raise ValueError("The challenge type " + challenge_type_name + " is unsupported")
        challenges = self.get_challenges()
        #print(challenges)
        cleaned_challenges = []
        for challenge in challenges:
            cleaned_challenge = {}
            for type in challenge["challenges"]:
                if type["type"] == challenge_type_name:
                    cleaned_challenge["type"] = challenge_type_name
                    cleaned_challenge["url"] = type["url"]
                    cleaned_challenge["domain"] = challenge["domain"]
                    cleaned_challenge["wildcard"] = challenge["wildcard"]
                    cleaned_challenge["token"] = type["token"]
                    cleaned_challenge["status"] = type["status"]
                    cleaned_challenges.append(cleaned_challenge)
                    break
        return cleaned_challenges

    def perform_challenge(self):
        challenges = self.get_challenges_from_type(challenge_type)
        for challenge in challenges:
            #print(challenge)
            public_key = {"crv": self.jwk_public_key["crv"],
                          "x": self.jwk_public_key["x"],
                          "y": self.jwk_public_key["y"]}
            json_key_auth = json.dumps(public_key, sort_keys=True, separators=(",", ":"))
            digest = hashes.Hash(hashes.SHA256())
            digest.update(json_key_auth.encode("utf8"))
            encoded_digest = acme_base64_encoding(digest.finalize())
            key_auth = challenge["token"] + "." + encoded_digest
            if challenge["type"] == "dns-01":
                digest = hashes.Hash(hashes.SHA256())
                digest.update(key_auth.encode("utf8"))
                encoded_rdata = acme_base64_encoding(digest.finalize())
                dns_records.append(DnsRecords(QTYPE.TXT,
                                              "_acme-challenge." + challenge["domain"],
                                              encoded_rdata))
            elif challenge["type"] == "http-01":
                global http_token
                global http_key_auth
                http_token = challenge["token"]
                http_key_auth = key_auth
            status = ""
            max_retries = 5
            while status != "valid":
                response = self.create_signed_acme_request(challenge["url"], {})
                status = response["status"]
                #print(response)
                #max_retries = max_retries - 1
                if max_retries <= 0:
                    raise StopIteration("Max retries reached!")
                time.sleep(2)


class DnsServerRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        try:
            print("DNS packet incoming...")
            question = DNSRecord.parse(data)
        except DNSError:
            print("Error decoding DNS packet!")
        else:
            questioned_domain = question.get_q().get_qname().__str__()
            answer = question.reply()
            any_q = question.get_q().qtype == QTYPE.ANY
            if question.get_q().qtype == QTYPE.A or any_q:
                answer.add_answer(RR(questioned_domain, QTYPE.A, rdata=A(dns_record_ip_address), ttl=DNS_TTL))
            for dns_record in dns_records:
                if question.get_q().qtype == dns_record.qtype or any_q:
                    if dns_record.qtype == QTYPE.TXT:
                        rdata = TXT(dns_record.rdata)
                    answer.add_answer(RR(dns_record.hostname, dns_record.qtype, rdata=rdata, ttl=DNS_TTL))
            reply = answer.pack()
            self.request[1].sendto(reply, self.client_address)


class ChallengeHttpServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/acme-challenge/" + http_token:
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(http_key_auth.encode("ascii"))
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("http-token: " + http_token + "<br/> http_key_auth: " + http_key_auth, "utf8"))


class CertificateHttpsServer(http.server.BaseHTTPRequestHandler):
    pass


class ShutdownHttpServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global shutdown
        if self.path == "/shutdown":
            shutdown = True
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("Shutdown command received...", "utf-8"))
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(
                "This server is only for shutting down the other servers. Please use \"/shutdown\" to shut down the servers!",
                "utf-8"))


if __name__ == "__main__":
    # Parse arguments from command line
    challenge_type = ""
    acme_directory_url = ""
    dns_record_ip_address = ""
    domains = list()
    revoke_certificate = False
    parser = argparse.ArgumentParser()
    challenge_type_parser = parser.add_subparsers(dest="challenge_type", help="ACME challenge type", required=True)
    challenge_type_parsers = list()
    challenge_type_parsers.append(challenge_type_parser.add_parser("dns01"))
    challenge_type_parsers.append(challenge_type_parser.add_parser("http01"))
    for ch_parser in challenge_type_parsers:
        ch_parser.add_argument("--dir", help="Directory URL of the ACME server", required=True)
        ch_parser.add_argument("--record", help="IPv4 address which will be returned by the DNS server", required=True)
        ch_parser.add_argument("--domain", help="Domain for  which to request the certificate. "
                                                "Can be applied multiple times", action="append",
                               required=True)
        ch_parser.add_argument("--revoke", help="Immediately revoke the certificate after obtaining it",
                               default=False, action="store_true", required=False)
    args = parser.parse_args(sys.argv[1:])
    challenge_type = args.challenge_type
    acme_directory_url = args.dir
    dns_record_ip_address = args.record
    domains = args.domain
    revoke_certificate = args.revoke

    dns_server = socketserver.ThreadingUDPServer(("", DNS_PORT), DnsServerRequestHandler)
    challenge_http_server = socketserver.ThreadingTCPServer(("", CHALLENGE_SERVER_PORT), ChallengeHttpServer)
    certificate_https_server = socketserver.ThreadingTCPServer(("", CERTIFICATE_SERVER_PORT),
                                                               CertificateHttpsServer)
    shutdown_http_server = socketserver.ThreadingTCPServer(("", SHUTDOWN_SERVER_PORT), ShutdownHttpServer)

    # Generate private key / public key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    print(
        "*************************************************************************************************************")
    print("To shutdown the server open the site http://" + str(shutdown_http_server.server_address[0]) + ":" + str(
        shutdown_http_server.server_address[1]) + "/shutdown")
    print(
        "*************************************************************************************************************")

    threads = [threading.Thread(target=dns_server.serve_forever),
               threading.Thread(target=challenge_http_server.serve_forever),
               threading.Thread(target=certificate_https_server.serve_forever),
               threading.Thread(target=shutdown_http_server.serve_forever)]
    for thread in threads:
        thread.daemon = True
        thread.start()
    try:
        client = AcmeClient(acme_directory_url)
        client.create_account()
        client.create_order()
        client.perform_challenge()
        while not shutdown:
            time.sleep(0.1)
    finally:
        dns_server.shutdown()
        challenge_http_server.shutdown()
        certificate_https_server.shutdown()
        shutdown_http_server.shutdown()
