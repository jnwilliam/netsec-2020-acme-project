import argparse
import sys
from datetime import datetime
from typing import Dict, Union, List
import requests
from http import server
import threading
import socketserver
import http
from dnslib import *
import time
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import rsa
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


class AcmeException(Exception):
    pass


class ServerImplementationError(AcmeException):
    pass


class ResourceNotAvailable(AcmeException):
    pass


class AcmeProtocolError(AcmeException):
    pass


class BadNonce(AcmeProtocolError):
    pass


class Log:
    def __init__(
            self,
            loglevel: int = 3,
            handler=print
    ):
        """
        :param loglevel: Log level from 0 (almost no output) to 3 (log everything)
        """
        self.loglevel = loglevel
        if loglevel < 0:
            self.loglevel = 0
        self.handler = handler

    def log(
            self,
            message,
            log_at_level:
            int = 1
    ):
        if log_at_level > self.loglevel:
            return
        time_stamp = datetime.now().strftime("[%Y.%m.%d - %H:%M:%S]    ")
        for line in iter(str(message).splitlines()):
            self.handler(time_stamp + str(line))

    def log_instance_creation(
            self,
            object_: object
    ):
        self.log("New object instantiated: {}".format(object_.__str__()), 3)


logger = Log(loglevel=3)


class DnsRecords:
    def __init__(
            self,
            qtype: QTYPE,
            hostname: string,
            rdata: string
    ):
        self.qtype = qtype
        self.hostname = hostname
        self.rdata = rdata


dns_challenge: Union[DnsRecords, None] = None


class Jose:
    def __init__(
            self,
            algorithm: str = "RS256"
    ):
        if algorithm not in ["RS256", "ES256"]:
            raise NotImplementedError("{} is not implemented!".format(algorithm))
        self.algorithm = "ES256"
        self.private_key = self._generate_keys()
        self.jwk = self._jwk()

    def _generate_keys(self) -> Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]:
        if self.algorithm == "ES256":
            return ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        elif self.algorithm == "RS256":
            return rsa.generate_private_key(65537, 2048, backend=default_backend())

    def _jwk(self) -> Dict[str, str]:
        if self.algorithm == "ES256":
            x = self.private_key.public_key().public_numbers().x
            y = self.private_key.public_key().public_numbers().y
            x_64 = Jose.base64_enc(x.to_bytes(32, "big"))
            y_64 = Jose.base64_enc(y.to_bytes(32, "big"))
            return {"kty": "EC",
                    "crv": "P-256",
                    "x": x_64,
                    "y": y_64}
        elif self.algorithm == "RS256":
            e = self.private_key.public_key().public_numbers().e
            n = self.private_key.public_key().public_numbers().n
            e_64 = Jose.base64_enc(e.to_bytes((e.bit_length() + 7) // 8, "big"))
            n_64 = Jose.base64_enc(n.to_bytes((n.bit_length() + 7) // 8, "big"))
            return {"kty": "RSA",
                    "e": e_64,
                    "n": n_64}

    def create_jose(
            self,
            payload,
            additional_headers: Dict[str, str] = None,
            kid: str = None
    ) -> Dict[str, str]:
        header = {"alg": self.algorithm}
        if additional_headers:
            header.update(additional_headers)
        if kid:
            header.update({"kid": kid})
        else:
            header.update({"jwk": self._jwk()})
        header_64 = Jose.base64_enc(json.dumps(header))
        payload_64 = ""
        if payload is not None:
            payload_64 = Jose.base64_enc(json.dumps(payload))
        signature_64 = Jose.base64_enc(self._sign("{}.{}".format(header_64, payload_64)))
        return {"protected": header_64,
                "payload": payload_64,
                "signature": signature_64}

    def _sign(
            self,
            message: Union[str, bytes]
    ) -> bytes:
        if isinstance(message, str):
            message = message.encode("utf8")
        if self.algorithm == "ES256":
            r, s = decode_dss_signature(self.private_key.sign(message, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        elif self.algorithm == "RS256":
            return self.private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    @staticmethod
    def base64_enc(
            data: Union[str, bytes]
    ) -> str:
        if isinstance(data, str):
            data = data.encode("utf8")
        encoded_data = base64.urlsafe_b64encode(data).rstrip(b'=')
        return encoded_data.decode("utf8")

    @staticmethod
    def base64_dec(
            data: str
    ) -> str:
        data += "=" * ((4 - len(data) % 4) % 4)
        decoded_data = base64.urlsafe_b64decode(data).decode("utf8")
        return decoded_data


class AcmeDirectory:
    def __init__(
            self,
            directory_url: str
    ):
        self.directory_url = directory_url
        self._dir_new_nonce: Union[str, None] = None
        self._dir_new_account: Union[str, None] = None
        self._dir_new_order: Union[str, None] = None
        self._dir_new_authz: Union[str, None] = None
        self._dir_revoke_cert: Union[str, None] = None
        self._dir_key_change: Union[str, None] = None
        self._parse_directory()

    def _parse_directory(self):
        response = requests.get(url=self.directory_url, verify=ACME_SERVER_CERTIFICATE_LOCATION)
        directory = response.json()
        logger.log("GET {} - {}".format(self.directory_url, response.status_code))
        try:
            self._dir_new_nonce = directory["newNonce"]
            self._dir_new_account = directory["newAccount"]
            self._dir_new_order = directory["newOrder"]
            self._dir_revoke_cert = directory["revokeCert"]
            self._dir_key_change = directory["keyChange"]
        except KeyError:
            raise ServerImplementationError("The directory response from the server is incomplete!")
        try:
            self._dir_new_authz = directory["newAuthz"]
        except KeyError:
            logger.log("newAuthz is not implemented on the server...")

    def get_new_nonce(self):
        return self._dir_new_nonce

    def get_new_account(self):
        return self._dir_new_account

    def get_new_order(self):
        return self._dir_new_order

    def get_revoke_cert(self):
        return self._dir_revoke_cert

    def get_key_change(self):
        return self._dir_key_change

    def get_new_authz(self):
        if self._dir_new_authz:
            return self._dir_new_authz
        raise ResourceNotAvailable("newAuthz resource is not available on this server!")


class AcmeRequest:
    def __init__(
            self,
            directory_url: str,
            account: Jose
    ):
        self.directory = AcmeDirectory(directory_url)
        self.account = account
        self.nonce = self._head(self.directory.get_new_nonce()).headers["Replay-Nonce"]
        logger.log("New Nonce: {}".format(self.nonce))

    def _post(
            self,
            url: str,
            payload: Union[Dict[str, Union[str, List, bool]], None],
            jose_headers: Dict[str, str] = None,
            kid: str = None,
            headers: Union[Dict[str, str], None] = None
    ) -> requests.Response:
        if not headers:
            headers = {}
        if not jose_headers:
            jose_headers = {}
        jose_headers.update({"url": url,
                             "nonce": self.nonce})
        body = json.dumps(self.account.create_jose(payload=payload, additional_headers=jose_headers, kid=kid))
        headers.update({"Content-Type": "application/jose+json"})
        response = requests.post(url=url, data=body, headers=headers, verify=ACME_SERVER_CERTIFICATE_LOCATION)
        logger.log("POST {} - {}".format(url, response.status_code))
        try:
            self._handle(response)
        except BadNonce:
            response = self._post(url=url, payload=payload, headers=headers)
        return response

    def _post_as_get(
            self,
            url: str,
            jose_headers: Dict[str, str] = None,
            kid: str = None,
            headers: Union[Dict[str, str], None] = None
    ) -> requests.Response:
        if not headers:
            headers = {}
        headers.update({"Content-Type": "application/jose+json"})
        response = self._post(url=url, payload=None, jose_headers=jose_headers, kid=kid, headers=headers)
        return response

    def _get(
            self,
            url: str,
            headers: Union[Dict[str, str],
                           None] = None
    ) -> requests.Response:
        response = requests.get(url=url, headers=headers, verify=ACME_SERVER_CERTIFICATE_LOCATION)
        logger.log("GET {} - {}".format(url, response.status_code))
        try:
            self._handle(response)
        except BadNonce:
            response = self._get(url=url, headers=headers)
        return response

    def _head(
            self,
            url: str,
            headers: Union[Dict[str, str],
                           None] = None
    ) -> requests.Response:
        response = requests.head(url=url, headers=headers, verify=ACME_SERVER_CERTIFICATE_LOCATION)
        try:
            self._handle(response)
        except BadNonce:
            response = self._head(url=url, headers=headers)
        return response

    def _handle(
            self,
            response: requests.Response,
            error_urn_space: str = "urn:ietf:params:acme:error:"
    ):
        self.nonce = response.headers["Replay-Nonce"]
        if 200 <= response.status_code < 300:
            return
        try:
            json_body = response.json()
            error = json_body["type"].replace(error_urn_space, "")
            description = json_body["detail"]
        except Exception:
            raise AcmeProtocolError("Generic Error ({}): {}".format(response.status_code, response.text))
        try:
            subproblems = json_body["subproblems"]
        except KeyError:
            subproblems = []
        logger.log("Error ({}) - {}: {}".format(response.status_code, error, description), 1)
        for subproblem in subproblems:
            logger.log(
                "    Subproblem - {}: {}".format(subproblem["type"].replace(error_urn_space, ""), subproblem["detail"]))
        if error == "badNonce":
            raise BadNonce(description)
        else:
            raise AcmeProtocolError("{}: {}".format(error, description))


class AcmeClient(AcmeRequest):
    def __init__(
            self,
            directory_url: str,
            account: Jose = Jose()
    ):
        super().__init__(directory_url, account)
        self.kid: Union[str, None] = None
        self.orders: List[AcmeOrder] = []

    def create_account(
            self,
            contacts: List[str] = None,
            contact_prefix: str = "mailto:",
            tos_agreed: bool = True
    ):
        prefixed_contacts = []
        if contacts:
            for contact in contacts:
                prefixed_contacts.append("{}{}".format(contact_prefix, contact))
        payload = {"termsOfServiceAgreed": tos_agreed}
        if prefixed_contacts:
            payload.update({"contact": prefixed_contacts})
        response = self._post(url=self.directory.get_new_account(),
                              payload=payload)
        self.kid = response.headers["Location"]

    def create_order(self,
                     domains_to_be_ordered: List[str]
                     ):
        if len(domains_to_be_ordered) == 0:
            raise ValueError("There must be at least one domain in the order!")
        payload = {"identifiers": []}
        for domain in domains_to_be_ordered:
            payload["identifiers"].append({"type": "dns", "value": domain})
        response = self._post(url=self.directory.get_new_order(),
                              payload=payload, kid=self.kid)
        self.orders.append(AcmeOrder(account_creation_response=response, client=self))

    def process_orders(self, challenge_type: str = "dns-01"):
        for order in self.orders:
            order.fullfill_order(challenge_type=challenge_type)


class AcmeOrder:
    def __init__(
            self,
            account_creation_response: requests.Response,
            client: AcmeClient
    ):
        response = account_creation_response.json()
        self.client = client
        self.order_url = account_creation_response.headers["Location"]
        self._status = response["status"]
        self.expires = datetime.strptime(response.get("expires", "2099-12-31T23:59:59Z"), "%Y-%m-%dT%H:%M:%SZ")
        self.not_before = datetime.strptime(response.get("notBefore", "1999-01-01T00:00:00Z"), "%Y-%m-%dT%H:%M:%SZ")
        self.not_after = datetime.strptime(response.get("notAfter", "2099-12-31T23:59:59Z"), "%Y-%m-%dT%H:%M:%SZ")
        self.domains = []
        for domain in response["identifiers"]:
            self.domains.append(domain["value"])
        self.finalize_url = response["finalize"]
        self.authorization_urls = response["authorizations"]
        self.certificate = response.get("certificate", None)
        self.authorizations: List[AcmeAuthorization] = []
        self._get_authorizations()

    def _get_authorizations(self):
        for authorization_url in self.authorization_urls:
            self.authorizations.append(AcmeAuthorization(authorization_url=authorization_url, client=self.client))

    def fullfill_order(self, challenge_type: str = "dns-01"):
        for authorization in self.authorizations:
            authorization.get_challenge(type_=challenge_type)
            authorization.perform_challenge(type_=challenge_type)


class AcmeAuthorization:
    def __init__(
            self,
            authorization_url: str,
            client: AcmeClient
    ):
        self.client = client
        self.authorization_url = authorization_url
        self.authorization_response = self.get_authorization()
        self.challenge: Union[AcmeChallenge, None] = None

    def get_challenge(
            self,
            type_: str = "dns-01"
    ) -> Dict[str, str]:
        for challenge in self.authorization_response.json()["challenges"]:
            if challenge["type"] == type_:
                return challenge

    def perform_challenge(
            self,
            type_: str = "dns-01"
    ):
        challenge = self.get_challenge(type_=type_)
        if type_ == "dns-01":
            self.challenge = DnsChallenge(token=challenge["token"],
                                          domain=self.authorization_response.json()["identifier"]["value"],
                                          account=self.client.account)
        elif type_ == "http-01":
            self.challenge = HttpChallenge(token=challenge["token"],
                                           domain=self.authorization_response.json()["identifier"]["value"],
                                           account=self.client.account)
        self.challenge.perform_challenge()
        self._respond_to_challenge(challenge["url"])
        self.poll_status(max_retries=10, poll_interval=2)

    def _respond_to_challenge(self, challenge_url: str):
        if self.challenge is None:
            raise AcmeException("There is no challenge to respond to!")
        self.client._post(url=challenge_url, payload={}, kid=self.client.kid)

    def poll_status(
            self,
            max_retries: int = 10,
            poll_interval: int = 2
    ):
        auth_done = False
        for i in range(max_retries):
            time.sleep(poll_interval)
            response = self.client._post_as_get(url=self.authorization_url, kid=self.client.kid).json()
            logger.log("{} Response: {}".format(i, response))
            if response["status"] in ["valid", "invalid"]:
                logger.log("Authorization is {}".format(response["status"]))
                auth_done = True
                if response["status"] != "valid":
                    raise AcmeException("Authorization invalid!")
                break
        if not auth_done:
            raise AcmeException("Failed to authorize!")

    def get_status(self) -> str:
        return self.get_authorization().json()["status"]

    def get_authorization(self) -> requests.Response:
        return self.client._post_as_get(url=self.authorization_url, kid=self.client.kid)


class AcmeChallenge:
    def __init__(
            self,
            token: str,
            domain: str,
            account: Jose
    ):
        self.token = token
        self.domain = domain
        self.account = account

    def base64_thumbprint(self) -> str:
        json_jwk = json.dumps(self.account.jwk, sort_keys=True, separators=(",", ":"))
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(json_jwk.encode("utf8"))
        return Jose.base64_enc(digest.finalize())

    def key_authorization(self) -> str:
        return "{}.{}".format(self.token, self.base64_thumbprint())

    def key_authorization_hash(self) -> str:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.key_authorization().encode("utf8"))
        return Jose.base64_enc(digest.finalize())

    def perform_challenge(self):
        raise NotImplementedError("You have to implement this function in a subclass!")


class DnsChallenge(AcmeChallenge):
    def perform_challenge(self):
        global dns_challenge
        hostname = "_acme-challenge.{}".format(self.domain)
        dns_challenge = DnsRecords(qtype=QTYPE.TXT,
                                   hostname=hostname,
                                   rdata=self.key_authorization_hash())

    def __del__(self):
        global dns_challenge
        dns_challenge = None


class HttpChallenge(AcmeChallenge):
    def perform_challenge(self):
        global http_token
        global http_key_auth
        http_token = self.token
        http_key_auth = self.key_authorization()

    def __del__(self):
        global http_token
        global http_key_auth
        http_token = None
        http_key_auth = None


class DnsServerRequestHandler(socketserver.BaseRequestHandler):
    def __init__(
            self,
            *args,
            **kwargs
    ):
        super().__init__(*args, **kwargs)

    def handle(self):
        global dns_challenge
        data = self.request[0].strip()
        try:
            logger.log("DNS packet incoming...")
            question = DNSRecord.parse(data)
        except DNSError:
            logger.log("Error decoding DNS packet!")
        else:
            questioned_domain = question.get_q().get_qname().__str__()
            answer = question.reply()
            any_q = question.get_q().qtype == QTYPE.ANY
            if question.get_q().qtype == QTYPE.A or any_q:
                answer.add_answer(RR(questioned_domain, QTYPE.A, rdata=A(dns_record_ip_address), ttl=DNS_TTL))
            if dns_challenge:
                if question.get_q().qtype == dns_challenge.qtype or any_q:
                    rdata = ""
                    if dns_challenge.qtype == QTYPE.TXT:
                        rdata = TXT(dns_challenge.rdata)
                    answer.add_answer(RR(dns_challenge.hostname, dns_challenge.qtype, rdata=rdata, ttl=DNS_TTL))
            reply = answer.pack()
            self.request[1].sendto(reply, self.client_address)


class ChallengeHttpServer(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class ShutdownHttpServer(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
                "This server is only for shutting down the other servers. "
                "Please use \"/shutdown\" to shut down the servers!",
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
    if args.challenge_type == "dns01":
        challenge_type = "dns-01"
    elif args.challenge_type == "http01":
        challenge_type = "http-01"
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
        client = AcmeClient(acme_directory_url, Jose("ES256"))
        client.create_account()
        client.create_order(domains_to_be_ordered=domains)
        client.process_orders(challenge_type=challenge_type)
        while not shutdown:
            shutdown = True
            time.sleep(0.1)
    finally:
        dns_server.shutdown()
        challenge_http_server.shutdown()
        certificate_https_server.shutdown()
        shutdown_http_server.shutdown()
