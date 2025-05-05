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
    try:
        return ssl_certificate.extensions.get_extension_for_oid(object_identifier)
    except X509ExtensionNotFound:
        return None


def usage():
    output_lines = [
        "crypto - crypto tools",
        "=======================",
        "- crypto host-check hostname[:port] ==> check the TLS certificate of a remote server",
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def consume_args():
    if len(argv) < 2 or argv[1] not in ["host-check"]:
        return None
    if argv[1] == "host-check":
        if len(argv) != 3:
            return None
        return {"action": "host-check", "target": argv[1]}
    return None


def main():
    args = consume_args()
    if not args:
        return usage()
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
