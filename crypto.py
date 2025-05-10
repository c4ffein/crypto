#!/usr/bin/env python

"""
crypto - crypto tools
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
"""

from cryptography.x509 import Certificate as X509Certificate
from cryptography.x509.oid import ObjectIdentifier
from enum import Enum
from sys import argv

# TODO Verify the whole chain is secure
# TODO Don't save anything in the current directory but a common dir instead

MAX_DEPTH = 4  # TODO Parameterize
TIMEOUT = 4  # TODO Parameterize

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])


class CryptoCliException(Exception):
    pass


def get_bytes_from_url(url: str) -> Optional[bytes]:
    try:
        response = requests.get(url)
        if response.status_code != 200:
            response.raise_for_status()
    except (HTTPError, RequestException) as exc:
        raise CryptoCliException(f"Unable to reach {url}") from exc
    return response.content


def write_to_file(obj: Any, filename: str) -> None:
    try:
        filename = f"TEMPFILES/{filename}"  # TODO better
        mode = "wb" if isinstance(obj, bytes) else "w"
        with open(filename, mode) as file:
            file.write(str(obj) if not isinstance(obj, bytes) else obj)
    except (IOError, TypeError) as exc:
        raise CryptoCliException(f"Failed to write to file {filename}") from exc


def get_certificate_from_url(url: str) -> X509Certificate:
    return load_pem_x509_certificate(DER_cert_to_PEM_cert(get_bytes_from_url(url)).encode("ascii"))


def get_ca_cert_pem() -> None:  # TODO Specify a better location
    write_to_file(get_bytes_from_url("https://curl.se/ca/cacert.pem"), "cacert.pem")


def get_hostname_and_port(host):
    try:
        host_port = host.split(":") if ":" in host else (host, 443)
        if len(host_port) != 2:
            raise Exception
        return host_port[0], int(host_port[1])
    except:
        raise CryptoCliException(f"Unable to parse host: {host}")


def get_certificate_from_hostname_and_port(
    hostname, port, secure: bool = True, timeout: Optional[int] = None
) -> X509Certificate:
    try:
        sock = create_socket(AF_INET, SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)
        wrapped_socket = create_default_context().wrap_socket(sock, server_hostname=hostname)
        wrapped_socket.connect((hostname, port))
        der_cert_bin = wrapped_socket.getpeercert(True)
        sha256 = sha256_hasher(der_cert_bin).hexdigest()
        print(f"SHA256: {sha256}")  # TODO Print in a better way?
        ssl_certificate = DER_cert_to_PEM_cert(der_cert_bin)
        return load_pem_x509_certificate(ssl_certificate.encode("ascii"))
    except SSLCertVerificationError as exc:
        raise CryptoCliException(f"Cert verification error: {hostname}:{port}") from exc
    except ConnectionRefusedError as exc:
        raise CryptoCliException(f"Connection refused: {hostname}:{port}") from exc


def get_cert_extension_or_none(
    ssl_certificate: X509Certificate, object_identifier: ObjectIdentifier
) -> Optional[X509Extension]:
    """
    The get_extension_for_oid doesn't handle the edge case where a certificate would have multiple AIA extensions
    Section 4.2 of RFC 5280 => "A certificate MUST NOT include more than one instance of a particular extension."
    """
    try:
        return ssl_certificate.extensions.get_extension_for_oid(object_identifier)
    except X509ExtensionNotFound:
        return None


def load_cacerts(filename: str) -> dict[str, str]:
    try:
        with open(filename, "r") as file:
            lines = [l.strip("\n").strip("\r") for l in file.readlines()]
    except FileNotFoundError as exc:
        raise CryptoCliException(f"cacert.pem not found: get it with the get-cacert verb") from exc
    begins = [i for i, l in enumerate(lines) if l.startswith(f"-----BEGIN CERTIFICATE-----")]
    ends = [i for i, l in enumerate(lines) if l.startswith(f"-----END CERTIFICATE-----")]
    if len(begins) != len(ends) or begins[0] < 2 or any(a >= b for a, b in zip(begins, ends)):
        raise CryptoCliException("cacert.pem could not be parsed")
    if any(not lines[i - 1].startswith("=====") for i in begins):
        raise CryptoCliException("cacert.pem could not be parsed")
    r = {lines[b - 2]: "\n".join(lines[i] for i in range(b, e + 1)) + "\n" for b, e in zip(begins, ends)}
    print(f"{len(r)} roots found in cacert.pem")


def usage():
    output_lines = [
        "crypto - crypto tools",
        "WARNING - NO CHAIN VERIFICATION FOR NOW",  # TODO fix and remove this warning
        "=====================",
        "- crypto host-check hostname[:port]               ==> check the TLS certificate of a remote server",
        "- crypto host-check hostname[:port] insecure=True ==> same but allows insecure connections",
        "- crypto get-cacert                               ==> get cacert.pem from curl.se, used to select a root CA",
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def consume_args():
    if len(argv) < 2 or argv[1] not in ["host-check", "get-cacert"]:
        return None
    if argv[1] == "host-check":
        if len(argv) not in [3, 4]:
            return None
        if len(argv) == 3:
            return {"action": "host-check", "target": argv[2], "insecure": False}
        if not any(argv[x].startswith("insecure=") for x in [2, 3]):
            return None
        return (
            lambda a, b: (
                {"action": "host-check", "target": argv[a], "insecure": argv[b][9:].upper() == "TRUE"}
                if argv[b][9:].upper() in ["TRUE", "FALSE"]
                else None
            )
        )(*((2, 3) if argv[3].startswith("insecure=") else (3, 2)))
    if argv[1] == "get-cacert":
        if len(argv) != 2:
            return None
        return {"action": "get-cacert"}
    return None


def main():
    args = consume_args()
    if not args:
        return usage()
    if args["action"] == "get-cacert":
        return get_ca_cert_pem()
    if args["action"] == "host-check":
        raise CryptoCliException("WiP I guess")
    else:
        return usage()


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n  !!  KeyboardInterrupt received  !!  \n")
        exit(-2)
    except CryptoCliException as e:
        print(f"{Color.RED.value}\n  !!  {e}  !!  \n")
        exit(-1)
    except Exception:
        raise
