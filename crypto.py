#!/usr/bin/env python

"""
crypto - KISS CLI crypto tools
MIT License - Copyright (c) 2025 c4ffein

Features:
- Full certificate chain verification with cryptographic signature validation
- Hostname verification (SAN/CN with wildcard support per RFC 6125)
- Certificate validity period checks
- Automatic chain traversal via AIA extensions
- Root CA verification against Mozilla's trusted root bundle
"""

import argparse
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256 as sha256_hasher
from pathlib import Path
from socket import AF_INET, SOCK_STREAM
from socket import socket as create_socket
from ssl import DER_cert_to_PEM_cert, SSLCertVerificationError, create_default_context
from typing import Any, Optional
from urllib.request import URLError, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509 import Certificate as X509Certificate
from cryptography.x509 import ExtensionNotFound as X509ExtensionNotFound
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.extensions import Extension as X509Extension
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

# TODO Don't save anything in the current directory but a common dir instead

SHARE_PATH = Path.home() / ".local" / "share" / "c4ffein-crypto-cli"

MAX_DEPTH = 4
TIMEOUT = 4
VERBOSE = False  # Global verbose flag

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])


class CryptoCliException(Exception):
    pass


def vprint(*args, **kwargs):
    """Print only if verbose mode is enabled."""
    if VERBOSE:
        print(*args, **kwargs)


def get_bytes_from_url(url: str) -> Optional[bytes]:
    try:
        response = urlopen(url)
        data = response.read()
    except URLError as e:
        raise CryptoCliException(f"Unable to reach {url}") from e
    if response.status != 200:
        raise CryptoCliException(f"Unable to reach {url}")
    return data


def write_to_file(obj: Any, filename: str) -> None:
    try:
        SHARE_PATH.mkdir(parents=True, exist_ok=True)
        filepath = SHARE_PATH / filename
        mode = "wb" if isinstance(obj, bytes) else "w"
        with filepath.open(mode) as file:
            file.write(str(obj) if not isinstance(obj, bytes) else obj)
    except (OSError, TypeError) as exc:
        raise CryptoCliException(f"Failed to write to file {filepath}") from exc


def get_certificate_from_url(url: str) -> X509Certificate:
    return load_pem_x509_certificate(DER_cert_to_PEM_cert(get_bytes_from_url(url)).encode("ascii"))


def get_ca_cert_pem() -> None:  # TODO Specify a better location
    write_to_file(get_bytes_from_url("https://curl.se/ca/cacert.pem"), "cacert.pem")


def get_hostname_and_port(host):
    try:
        host_port = host.split(":") if ":" in host else (host, 443)
        if len(host_port) != 2:
            raise ValueError("Invalid host format")
        return host_port[0], int(host_port[1])
    except (ValueError, IndexError) as exc:
        raise CryptoCliException(f"Unable to parse host: {host}") from exc


def get_certificate_from_hostname_and_port(
    hostname, port, secure: bool = True, timeout: Optional[int] = None
) -> X509Certificate:
    try:
        vprint(f"{Color.DIM.value}Connecting to {hostname}:{port}...")
        sock = create_socket(AF_INET, SOCK_STREAM)
        if timeout:
            sock.settimeout(timeout)
        wrapped_socket = create_default_context().wrap_socket(sock, server_hostname=hostname)
        wrapped_socket.connect((hostname, port))
        der_cert_bin = wrapped_socket.getpeercert(True)
        sha256 = sha256_hasher(der_cert_bin).hexdigest()
        vprint(f"Certificate SHA256: {sha256}")
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


def verify_certificate_signature(cert: X509Certificate, issuer_cert: X509Certificate) -> None:
    """
    Verify that cert was signed by issuer_cert's private key.
    Raises CryptoCliException if signature verification fails.
    """
    try:
        issuer_public_key = issuer_cert.public_key()
        signature_hash_algorithm = cert.signature_hash_algorithm

        if signature_hash_algorithm is None:
            raise CryptoCliException("Certificate uses unsupported signature algorithm (no hash)")

        # Verify based on key type
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(signature_hash_algorithm),
            )
        elif isinstance(issuer_public_key, dsa.DSAPublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            # EdDSA doesn't use a separate hash algorithm
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
            )
        else:
            raise CryptoCliException(f"Unsupported public key type: {type(issuer_public_key).__name__}")

    except InvalidSignature as e:
        raise CryptoCliException("Certificate signature verification failed") from e
    except Exception as e:
        raise CryptoCliException(f"Error during signature verification: {e}") from e


def check_certificate_validity(cert: X509Certificate) -> None:
    """
    Check if certificate is currently valid (not expired or not yet valid).
    Raises CryptoCliException if certificate is not valid.
    """
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        raise CryptoCliException(f"Certificate not yet valid (valid from {cert.not_valid_before_utc})")
    if now > cert.not_valid_after_utc:
        raise CryptoCliException(f"Certificate expired (expired on {cert.not_valid_after_utc})")
    vprint(f"Certificate valid: {cert.not_valid_before_utc} to {cert.not_valid_after_utc}")


def verify_hostname(cert: X509Certificate, hostname: str) -> None:
    """
    Verify that the certificate is valid for the given hostname.
    Checks both Subject Alternative Names (SAN) and Common Name (CN).
    Raises CryptoCliException if hostname doesn't match.
    """
    from cryptography.x509 import DNSName

    # First check SAN extension (preferred method per RFC 6125)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_dns_names = san_ext.value.get_values_for_type(DNSName)

        for san_name in san_dns_names:
            if _match_hostname(hostname, san_name):
                print(f"{Color.GREEN.value}✓ Hostname verified: {hostname} matches SAN {san_name}")
                return
    except X509ExtensionNotFound:
        # No SAN extension, fall back to CN
        pass

    # Fallback to Common Name in Subject
    try:
        cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attributes:
            cn = cn_attributes[0].value
            if _match_hostname(hostname, cn):
                print(f"{Color.GREEN.value}✓ Hostname verified: {hostname} matches CN {cn}")
                return
    except Exception:
        pass

    raise CryptoCliException(f"Hostname {hostname} does not match certificate")


def _match_hostname(hostname: str, cert_name: str) -> bool:
    """
    Match hostname against a certificate name, supporting wildcards.
    Implements RFC 6125 wildcard matching rules.
    """
    hostname = hostname.lower()
    cert_name = cert_name.lower()

    # Exact match
    if hostname == cert_name:
        return True

    # Wildcard match (*.example.com matches foo.example.com but not example.com or foo.bar.example.com)
    if cert_name.startswith("*."):
        cert_base = cert_name[2:]
        # Hostname must have exactly one more label than the wildcard pattern
        if "." in hostname:
            hostname_base = hostname.split(".", 1)[1]
            return hostname_base == cert_base

    return False


def load_cacerts(filename: str) -> dict[str, str]:
    try:
        with Path(filename).open() as file:
            lines = [line.strip("\n").strip("\r") for line in file]
    except FileNotFoundError as exc:
        raise CryptoCliException("cacert.pem not found: get it with 'crypto get-cacert'") from exc
    begins = [i for i, line in enumerate(lines) if line.startswith("-----BEGIN CERTIFICATE-----")]
    ends = [i for i, line in enumerate(lines) if line.startswith("-----END CERTIFICATE-----")]
    if len(begins) != len(ends) or begins[0] < 2 or any(a >= b for a, b in zip(begins, ends)):
        raise CryptoCliException("cacert.pem could not be parsed")
    if any(not lines[i - 1].startswith("=====") for i in begins):
        raise CryptoCliException("cacert.pem could not be parsed")
    certs = {lines[b - 2]: "\n".join(lines[i] for i in range(b, e + 1)) + "\n" for b, e in zip(begins, ends)}
    vprint(f"{len(certs)} root CAs loaded from cacert.pem")
    return {name: load_pem_x509_certificate(cert.encode()) for name, cert in certs.items()}


class CertStore:
    def __init__(self, file_path: str, max_chain_depth: int, hostname: Optional[str] = None):
        self.cacerts, self.max_chain_depth = load_cacerts(file_path), max_chain_depth
        self.hostname = hostname

    def start_chain_traversal(self, certificate: X509Certificate):
        # Verify hostname on the leaf certificate (depth 0)
        if self.hostname:
            verify_hostname(certificate, self.hostname)
        self.chain_traversal_step(certificate, 0)

    def chain_traversal_step(self, ssl_certificate: X509Certificate, depth: int) -> None:
        if depth >= self.max_chain_depth:
            raise CryptoCliException("Chain length overflow")

        # Check certificate validity period
        check_certificate_validity(ssl_certificate)

        cert_aki = get_cert_extension_or_none(ssl_certificate, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        cert_aki_value = cert_aki._value.key_identifier if cert_aki is not None else None
        if cert_aki_value is None:
            # Self-signed root certificate
            if ssl_certificate.issuer != ssl_certificate.subject:
                raise CryptoCliException("Followed chain to a non-root CA without an AKI")
            if ssl_certificate not in self.cacerts.values():
                raise CryptoCliException("Followed chain to a root CA not present in cacert.pem")
            # Verify self-signature
            verify_certificate_signature(ssl_certificate, ssl_certificate)
            print(f"{Color.GREEN.value}✓ Root CA found and verified: {ssl_certificate.subject.rfc4514_string()}")
            return

        aia = get_cert_extension_or_none(ssl_certificate, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        aia_uri_list = (
            [item.access_location._value for item in list(aia.value) if item.access_method._name == "caIssuers"]
            if aia is not None
            else []
        )
        if aia_uri_list:
            for item in aia_uri_list:
                vprint(f"{Color.DIM.value}Fetching issuer from: {item}")
                next_cert = get_certificate_from_url(item)
                # Verify this certificate was signed by the next one in the chain
                verify_certificate_signature(ssl_certificate, next_cert)
                vprint(f"{Color.GREEN.value}✓ Signature verified for: {ssl_certificate.subject.rfc4514_string()}")
                self.chain_traversal_step(next_cert, depth + 1)
            return

        vprint(f"{Color.DIM.value}No AIA found, searching direct link from cacert.pem")
        for root_ca_name, cert in self.cacerts.items():
            ski = get_cert_extension_or_none(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            if ski is None:
                continue  # Skip certs without SKI when looking for a match
            if ski.value.digest.hex() == cert_aki_value.hex():
                # Verify this certificate was signed by the root CA
                verify_certificate_signature(ssl_certificate, cert)
                # Verify root CA self-signature
                verify_certificate_signature(cert, cert)
                print(f"{Color.GREEN.value}✓ Root CA found and verified: {root_ca_name}")
                print(f"{Color.GREEN.value}✓ Chain signature verification complete")
                return
        raise CryptoCliException("Root CA not found")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="crypto",
        description="KISS CLI crypto tools for TLS certificate verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # host-check subcommand
    host_check_parser = subparsers.add_parser("host-check", help="Check the TLS certificate of a remote server")
    host_check_parser.add_argument("target", help="Hostname or hostname:port (default port: 443)")
    host_check_parser.add_argument(
        "--insecure", action="store_true", help="Allow insecure connections (skip initial SSL verification)"
    )
    host_check_parser.add_argument(
        "--timeout", type=int, default=TIMEOUT, help=f"Connection timeout in seconds (default: {TIMEOUT})"
    )
    host_check_parser.add_argument(
        "--max-depth", type=int, default=MAX_DEPTH, help=f"Maximum certificate chain depth (default: {MAX_DEPTH})"
    )
    host_check_parser.add_argument(
        "--expect-fail",
        action="store_true",
        help="Expect the verification to fail (for testing)",
    )

    # get-cacert subcommand
    subparsers.add_parser("get-cacert", help="Download cacert.pem from curl.se")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return None

    return args


def main():
    global VERBOSE
    args = parse_args()
    if not args:
        return -1

    VERBOSE = args.verbose

    if args.command == "get-cacert":
        get_ca_cert_pem()
        print(f"{Color.GREEN.value}✓ cacert.pem downloaded to {SHARE_PATH / 'cacert.pem'}")
        return 0

    if args.command == "host-check":
        try:
            hostname, port = get_hostname_and_port(args.target)
            certificate = get_certificate_from_hostname_and_port(
                hostname, port, secure=not args.insecure, timeout=args.timeout
            )
            certificate_manager = CertStore(SHARE_PATH / "cacert.pem", args.max_depth, hostname=hostname)
            certificate_manager.start_chain_traversal(certificate)
            print(f"{Color.GREEN.value}✓ Certificate chain verification complete!")

            if args.expect_fail:
                print(f"{Color.RED.value}ERROR: Expected failure but verification succeeded")
                return 1
            return 0
        except CryptoCliException as e:
            if args.expect_fail:
                vprint(f"Verification failed as expected: {e}")
                print(f"{Color.GREEN.value}✓ Failed as expected")
                return 0
            else:
                raise  # Re-raise to be caught by main exception handler

    return -1


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
