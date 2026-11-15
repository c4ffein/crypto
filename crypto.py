#!/usr/bin/env python

"""
crypto - KISS CLI crypto tools
MIT License - Copyright (c) 2025 c4ffein

I wouldn't recommend to use this if you are not aware of the security implications

Features:
- Full certificate chain verification with cryptographic signature validation
- Hostname verification (SAN/CN with wildcard support per RFC 6125)
- Certificate validity period checks
- Issuer checks (basicConstraints CA flag, path length, keyUsage keyCertSign)
- Automatic chain traversal via AIA extensions
- Root CA verification against Mozilla's trusted root bundle
"""

import argparse
import os
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256 as sha256_hasher
from http.client import HTTPException
from pathlib import Path
from socket import create_connection, gaierror
from ssl import DER_cert_to_PEM_cert, SSLCertVerificationError, create_default_context
from typing import Any
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, build_opener

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509 import Certificate as X509Certificate
from cryptography.x509 import ExtensionNotFound as X509ExtensionNotFound
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.extensions import Extension as X509Extension
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID, ObjectIdentifier

SHARE_PATH = Path.home() / ".local" / "share" / "c4ffein-crypto-cli"

MAX_DEPTH = 4
TIMEOUT = 4
VERBOSE = False  # Global verbose flag
FINGERPRINT = False  # When set, stdout is reserved for the machine-readable fingerprint; status goes to stderr

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])


class CryptoCliException(Exception):
    pass


class CryptoCliNetworkException(CryptoCliException):
    """The host could not be reached at all: no verification verdict, so --expect-fail must not swallow it."""


def vprint(*args, **kwargs):
    """Print only if verbose mode is enabled. Routed to stderr in --fingerprint mode to keep stdout clean."""
    if VERBOSE:
        if FINGERPRINT:
            kwargs.setdefault("file", sys.stderr)
        print(*args, **kwargs)


def status_print(*args, **kwargs):
    """Print user-facing status. Routed to stderr in --fingerprint mode so stdout stays machine-readable."""
    if FINGERPRINT:
        kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


class CheckedRedirectHandler(HTTPRedirectHandler):
    """Re-check every redirect hop: urllib follows redirects itself, so validating only the first URL is not enough."""

    def __init__(self, validate_url: Callable[[str], None] | None):
        self.validate_url = validate_url

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme != urlparse(req.full_url).scheme:
            raise CryptoCliException(f"URL redirected to different scheme: {req.full_url} -> {newurl}")
        if self.validate_url is not None:
            self.validate_url(newurl)
        vprint(f"{Color.DIM.value}Redirected to: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def get_bytes_from_url(
    url: str, timeout: int = 10, max_size: int = 1024 * 1024, validate_url: Callable[[str], None] | None = None
) -> bytes:
    """
    Fetch bytes from URL with security validations.

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds
        max_size: Maximum allowed response size in bytes
        validate_url: Optional check applied to the initial URL and to every redirect target; raises to refuse
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise CryptoCliException(f"Invalid URL scheme: {parsed.scheme}")
    if validate_url is not None:
        validate_url(url)

    try:
        with build_opener(CheckedRedirectHandler(validate_url)).open(url, timeout=timeout) as response:
            status = response.status
            # Read with size limit to prevent memory exhaustion
            data = response.read(max_size + 1)
    except (OSError, HTTPException) as e:  # URLError, timeouts, resets, truncated or malformed responses
        raise CryptoCliException(f"Unable to reach {url}") from e

    if status != 200:
        raise CryptoCliException(f"Unable to reach {url}")
    if len(data) > max_size:
        raise CryptoCliException(f"Response too large (>{max_size} bytes)")

    return data


def write_to_file(obj: Any, filename: str) -> None:
    filepath = SHARE_PATH / filename
    try:
        SHARE_PATH.mkdir(parents=True, exist_ok=True)
        data = obj if isinstance(obj, bytes) else str(obj).encode()
        # Atomic write: temp file in the same directory, then rename over the destination
        temp_fd, temp_name = tempfile.mkstemp(dir=SHARE_PATH, prefix=f".{filename}.")
        temp_path = Path(temp_name)
        try:
            try:
                os.write(temp_fd, data)
            finally:
                os.close(temp_fd)
            temp_path.chmod(0o644)  # mkstemp creates 0o600; the CA bundle is public
            temp_path.replace(filepath)
        except BaseException:
            temp_path.unlink(missing_ok=True)
            raise
    except (OSError, TypeError) as exc:
        raise CryptoCliException(f"Failed to write to file {filepath}") from exc


def validate_aia_url(url: str) -> None:
    """
    Validate AIA (Authority Information Access) URL to prevent SSRF attacks.

    AIA URLs come from the certificate chain and are therefore attacker-influenced.
    We resolve the hostname and require *every* resolved address to be globally
    routable. ipaddress.is_global rejects private (RFC 1918 / RFC 4193), loopback,
    link-local (including the 169.254.169.254 cloud-metadata endpoint) and reserved
    ranges in a single allowlist-style check. get_certificate_from_url applies this
    to the AIA URL and to every redirect hop.

    Residual risk: urlopen re-resolves the hostname when it connects, so a fast-
    flipping DNS record could rebind to a private address between this check and the
    fetch (TOCTOU / DNS rebinding). Fully closing that requires connecting to the
    validated IP directly and passing the hostname only for Host/SNI.

    Args:
        url: The AIA URL to validate

    Raises:
        CryptoCliException: If URL points to a dangerous destination
    """
    from ipaddress import ip_address
    from socket import getaddrinfo

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise CryptoCliException(f"AIA URL has invalid scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise CryptoCliException(f"AIA URL has no hostname: {url}")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise CryptoCliException(f"AIA URL has invalid port: {url}") from exc

    try:
        infos = getaddrinfo(parsed.hostname, port)
    except (OSError, UnicodeError) as exc:
        raise CryptoCliException(f"AIA URL host does not resolve: {parsed.hostname}") from exc

    for addr in {info[4][0] for info in infos}:
        ip = ip_address(addr.split("%")[0])  # strip any IPv6 zone id
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped  # ::ffff:10.0.0.1 must be judged as 10.0.0.1, not as a v6 address
        if not ip.is_global:
            raise CryptoCliException(f"AIA URL resolves to non-global address {addr}: {parsed.hostname}")


def get_certificate_from_url(url: str) -> X509Certificate:
    """Fetch and parse certificate from URL, with SSRF protection on the URL and on every redirect hop."""
    data = get_bytes_from_url(url, validate_url=validate_aia_url)
    try:
        return load_pem_x509_certificate(DER_cert_to_PEM_cert(data).encode("ascii"))
    except ValueError as exc:
        raise CryptoCliException(f"AIA URL did not return a DER certificate: {url}") from exc


def get_ca_cert_pem() -> None:
    """Download Mozilla's CA certificate bundle to ~/.local/share/c4ffein-crypto-cli/cacert.pem"""
    write_to_file(get_bytes_from_url("https://curl.se/ca/cacert.pem"), "cacert.pem")


def get_hostname_and_port(host):
    try:
        host_port = host.split(":") if ":" in host else (host, 443)
        if len(host_port) != 2:
            raise ValueError("Invalid host format")
        hostname, port = host_port[0], int(host_port[1])
        if not hostname or not 0 < port < 65536:
            raise ValueError("Invalid host format")
        return hostname, port
    except (ValueError, IndexError) as exc:
        raise CryptoCliException(f"Unable to parse host: {host}") from exc


def get_certificate_from_hostname_and_port(hostname, port, timeout: int | None = None) -> X509Certificate:
    try:
        vprint(f"{Color.DIM.value}Connecting to {hostname}:{port}...")
        # create_connection resolves through getaddrinfo, so both IPv4 and IPv6 hosts work
        with create_connection((hostname, port), timeout=timeout) as sock:
            with create_default_context().wrap_socket(sock, server_hostname=hostname) as wrapped_socket:
                der_cert_bin = wrapped_socket.getpeercert(True)
        sha256 = sha256_hasher(der_cert_bin).hexdigest()
        vprint(f"Certificate SHA256: {sha256}")
        ssl_certificate = DER_cert_to_PEM_cert(der_cert_bin)
        return load_pem_x509_certificate(ssl_certificate.encode("ascii"))
    except SSLCertVerificationError as exc:
        raise CryptoCliException(f"Cert verification error: {hostname}:{port}") from exc
    except ConnectionRefusedError as exc:
        raise CryptoCliNetworkException(f"Connection refused: {hostname}:{port}") from exc
    except TimeoutError as exc:
        raise CryptoCliNetworkException(f"Connection timed out: {hostname}:{port}") from exc
    except gaierror as exc:
        raise CryptoCliNetworkException(f"Unable to resolve host: {hostname}") from exc
    except UnicodeError as exc:  # hostname that cannot be IDNA-encoded
        raise CryptoCliNetworkException(f"Invalid hostname: {hostname}") from exc
    except OSError as exc:  # unreachable network, reset, TLS handshake failure other than cert verification...
        raise CryptoCliNetworkException(f"Connection error: {hostname}:{port} ({exc})") from exc


def get_cert_extension_or_none(
    ssl_certificate: X509Certificate, object_identifier: ObjectIdentifier
) -> X509Extension | None:
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
        if isinstance(issuer_public_key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            # EdDSA has no separate hash algorithm (signature_hash_algorithm is None): handle it before the hash check
            issuer_public_key.verify(cert.signature, cert.tbs_certificate_bytes)
            return

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
    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        raise CryptoCliException(f"Certificate not yet valid (valid from {cert.not_valid_before_utc})")
    if now > cert.not_valid_after_utc:
        raise CryptoCliException(f"Certificate expired (expired on {cert.not_valid_after_utc})")
    vprint(f"Certificate valid: {cert.not_valid_before_utc} to {cert.not_valid_after_utc}")


def check_issuer_constraints(issuer_cert: X509Certificate, intermediates_below: int) -> None:
    """
    Check that issuer_cert is allowed to sign other certificates (RFC 5280 4.2.1.9 and 4.2.1.3).
    Without this, the holder of any valid leaf certificate could act as a CA and issue for any hostname.
    intermediates_below is the number of intermediate CA certificates between issuer_cert and the leaf.
    Raises CryptoCliException if issuer_cert may not act as the issuer at that position.
    """
    name = issuer_cert.subject.rfc4514_string()
    basic_constraints = get_cert_extension_or_none(issuer_cert, ExtensionOID.BASIC_CONSTRAINTS)
    if basic_constraints is None or not basic_constraints.value.ca:
        raise CryptoCliException(f"Issuer certificate is not a CA (basicConstraints): {name}")
    path_length = basic_constraints.value.path_length
    if path_length is not None and intermediates_below > path_length:
        raise CryptoCliException(f"Issuer certificate path length constraint exceeded: {name}")
    key_usage = get_cert_extension_or_none(issuer_cert, ExtensionOID.KEY_USAGE)
    if key_usage is not None and not key_usage.value.key_cert_sign:
        raise CryptoCliException(f"Issuer certificate may not sign certificates (keyUsage): {name}")


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
                status_print(
                    f"{Color.GREEN.value}✓{Color.WHITE.value} Hostname verified: {hostname} matches SAN {san_name}"
                )
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
                status_print(f"{Color.GREEN.value}✓{Color.WHITE.value} Hostname verified: {hostname} matches CN {cn}")
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


def load_cacerts(filename: str) -> dict[str, X509Certificate]:
    parse_error = "cacert.pem could not be parsed: refresh it with 'crypto get-cacert'"
    try:
        with Path(filename).open(encoding="utf-8") as file:
            lines = [line.strip("\n").strip("\r") for line in file]
    except FileNotFoundError as exc:
        raise CryptoCliException("cacert.pem not found: get it with 'crypto get-cacert'") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise CryptoCliException("cacert.pem could not be read") from exc
    begins = [i for i, line in enumerate(lines) if line.startswith("-----BEGIN CERTIFICATE-----")]
    ends = [i for i, line in enumerate(lines) if line.startswith("-----END CERTIFICATE-----")]
    if not begins or len(begins) != len(ends) or any(a >= b for a, b in zip(begins, ends, strict=True)):
        raise CryptoCliException(parse_error)
    certs = {}
    for begin, end in zip(begins, ends, strict=True):
        # Layout: name, "=====" underline, optional "# ..." comment lines (newer bundles add a fingerprint), then BEGIN
        underline = begin - 1
        while underline > 0 and lines[underline].startswith("#"):
            underline -= 1
        if underline < 1 or not lines[underline].startswith("====="):
            raise CryptoCliException(parse_error)
        certs[lines[underline - 1]] = "\n".join(lines[begin : end + 1]) + "\n"
    vprint(f"{len(certs)} root CAs loaded from cacert.pem")
    try:
        return {name: load_pem_x509_certificate(cert.encode()) for name, cert in certs.items()}
    except ValueError as exc:
        raise CryptoCliException(parse_error) from exc


class CertStore:
    def __init__(self, file_path: str, max_chain_depth: int, hostname: str | None = None):
        self.cacerts, self.max_chain_depth = load_cacerts(file_path), max_chain_depth
        self.hostname = hostname

    def start_chain_traversal(self, certificate: X509Certificate):
        # Verify hostname on the leaf certificate (depth 0)
        if self.hostname:
            verify_hostname(certificate, self.hostname)
        self.chain_traversal_step(certificate, 0)

    def chain_traversal_step(self, ssl_certificate: X509Certificate, depth: int) -> None:  # noqa: C901
        if depth >= self.max_chain_depth:
            raise CryptoCliException("Chain length overflow")
        # Check certificate validity period
        check_certificate_validity(ssl_certificate)
        cert_aki = get_cert_extension_or_none(ssl_certificate, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        cert_aki_value = cert_aki.value.key_identifier if cert_aki is not None else None
        # Check root cert as no aki
        if cert_aki_value is None:
            # Self-signed root certificate
            if ssl_certificate.issuer != ssl_certificate.subject:
                raise CryptoCliException("Followed chain to a non-root CA without an AKI")
            if ssl_certificate not in self.cacerts.values():
                raise CryptoCliException("Followed chain to a root CA not present in cacert.pem")
            # Verify self-signature
            verify_certificate_signature(ssl_certificate, ssl_certificate)
            status_print(
                f"{Color.GREEN.value}✓{Color.WHITE.value} Root CA found and verified: "
                f"{ssl_certificate.subject.rfc4514_string()}"
            )
            return
        # Check root cert in cacert.pem anyway
        vprint(f"{Color.DIM.value}First searching direct link from cacert.pem")
        # First try to match by SKI/AKI in roots
        for root_ca_name, cert in self.cacerts.items():
            ski = get_cert_extension_or_none(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            if ski is None:
                continue  # Skip certs without SKI when looking for a match
            if ski.value.digest.hex() == cert_aki_value.hex():
                # The root itself must be within its validity period (the other root paths already check this)
                check_certificate_validity(cert)
                # Verify this certificate was signed by the root CA
                verify_certificate_signature(ssl_certificate, cert)
                # Verify root CA self-signature
                verify_certificate_signature(cert, cert)
                status_print(f"{Color.GREEN.value}✓{Color.WHITE.value} Root CA found and verified: {root_ca_name}")
                status_print(f"{Color.GREEN.value}✓{Color.WHITE.value} Chain signature verification complete")
                return
        # Fallback: try matching by public key (handles cross-signed intermediates)
        # If we have a cross-signed intermediate, find the self-signed root with same public key
        #
        # SECURITY NOTE: Cross-signed certificates explained:
        # A cross-signed intermediate has:
        #   - Subject: CN=SomeCA
        #   - Issuer: CN=DifferentRoot (the cross-signer)
        #   - Public Key: Kpub (belongs to SomeCA)
        #   - Signed by: DifferentRoot's private key
        #
        # There's also a self-signed root with:
        #   - Subject: CN=SomeCA
        #   - Issuer: CN=SomeCA (itself)
        #   - Public Key: Kpub (SAME key!)
        #   - Signed by: SomeCA's own private key
        #
        # These represent the SAME CA (same key pair), just with different issuers.
        # We can securely identify them by comparing public keys.
        #
        # SECURITY: Why public key matching is secure:
        # 1. An attacker cannot forge a certificate with a trusted root's public key
        #    without having the corresponding private key
        # 2. If they try to use the real public key in a fake cert, signature
        #    verification will fail when validating the previous cert in the chain
        #    (because they don't have the private key to sign with)
        # 3. The chain up to this point was already validated via signatures
        #
        # This is cryptographically secure because:
        # - Public keys are unforgeable (discrete log problem)
        # - Chain validation ensures this cert's public key was used to sign the previous cert
        # - Therefore, whoever controls this cert also controls the private key
        # - If public keys match, they represent the same CA
        vprint(f"{Color.DIM.value}Trying public key match without SKI match for intermediate cert...")
        # Extract the public key from the current certificate
        from cryptography.hazmat.primitives import serialization

        current_pubkey_bytes = ssl_certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # SECURITY: Public key matching should only apply to intermediate certificates (depth > 0)
        # Leaf certificates (depth=0) should NEVER have a public key matching a trusted root CA
        # This is defense-in-depth: even though TLS handshake protects us, the logic itself should reject this
        for root_ca_name, cert in self.cacerts.items():
            if cert.subject == cert.issuer:  # Only consider self-signed roots
                root_pubkey_bytes = cert.public_key().public_bytes(
                    encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                if current_pubkey_bytes == root_pubkey_bytes:
                    # Found matching public key - behavior depends on depth
                    if depth == 0:
                        # Leaf certificate with root's public key - reject (defense-in-depth)
                        raise CryptoCliException(
                            "Leaf certificate cannot be matched by public key to a trusted root. "
                            "Leaf certificates must have unique key pairs."
                        )
                    else:
                        # Intermediate with root's public key - accept as cross-signed cert
                        try:
                            # Verify the root is self-signed (prevents forged roots in cacert.pem)
                            verify_certificate_signature(cert, cert)
                            vprint(f"{Color.GREEN.value}✓ Found trusted root with matching public key: {root_ca_name}")
                            vprint(
                                f"{Color.GREEN.value}✓ Cross-signed certificate verified (same CA, different issuer)"
                            )
                            # Now continue chain traversal with the trusted self-signed root
                            self.chain_traversal_step(cert, depth)
                            return
                        except CryptoCliException:
                            # Signature verification failed, continue searching
                            continue
        vprint(f"{Color.DIM.value}Then tries to follow the chain")
        # Tries to follow the AIA
        aia = get_cert_extension_or_none(ssl_certificate, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        aia_uri_list = (
            [
                item.access_location.value
                for item in aia.value
                if item.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            ]
            if aia is not None
            else []
        )
        if aia_uri_list:
            for item in aia_uri_list:
                vprint(f"{Color.DIM.value}Fetching issuer from: {item}")
                next_cert = get_certificate_from_url(item)
                # The fetched issuer is untrusted input: it must be a CA allowed to sign at this position.
                # (Roots from cacert.pem are trust anchors, trusted a priori, so they are not subject to this.)
                check_issuer_constraints(next_cert, depth)
                # Verify this certificate was signed by the next one in the chain
                verify_certificate_signature(ssl_certificate, next_cert)
                vprint(
                    f"{Color.GREEN.value}✓{Color.WHITE.value} Signature verified for: "
                    f"{ssl_certificate.subject.rfc4514_string()}"
                )
                self.chain_traversal_step(next_cert, depth + 1)
            return
        raise CryptoCliException("Broken chain")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="crypto",
        description="KISS CLI crypto tools for TLS certificate verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,  # We'll handle help ourselves for KISS aesthetic
    )

    parser.add_argument("-h", "--help", action="store_true", help="Show this help message")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # host-check subcommand
    host_check_parser = subparsers.add_parser("host-check", help="Check the TLS certificate of a remote server")
    host_check_parser.add_argument("target", help="Hostname or hostname:port (default port: 443)")
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
    host_check_parser.add_argument(
        "--fingerprint",
        action="store_true",
        help="On success, print only the leaf certificate's SHA256 fingerprint (hex) to stdout",
    )

    # get-cacert subcommand
    subparsers.add_parser("get-cacert", help="Download cacert.pem from curl.se")

    args = parser.parse_args()

    if args.help or not args.command:
        print_help()
        return None

    return args


def print_help():
    D, W = Color.DIM.value, Color.WHITE.value
    """Print KISS-style help message"""
    help_text = f"""
crypto - crypto tools
─────────────────────
{D}- {W}crypto host-check hostname[:port]                 {D}── check the TLS certificate of a remote server
{D}- {D}crypto host-check hostname[:port] {W}--timeout N     {D}── set connection timeout (default: 4s)
{D}- {D}crypto host-check hostname[:port] {W}--max-depth N   {D}── set max chain depth (default: 4)
{D}- {D}crypto host-check hostname[:port] {W}--expect-fail   {D}── expect verification to fail (for testing)
{D}- {D}crypto host-check hostname[:port] {W}--fingerprint   {D}── on success, print only the SHA256 fingerprint (hex)
{D}- {W}crypto get-cacert                                 {D}── get cacert.pem from curl.se, used to select a root CA{W}
─────────────────────
Global options:
  -v, --verbose                                     {D}── enable detailed output{W}
  -h, --help                                        {D}── show this help message{W}
"""
    print(help_text)


def main():
    global VERBOSE, FINGERPRINT
    args = parse_args()
    if not args:
        return 0  # Help was shown, not an error

    VERBOSE = args.verbose
    FINGERPRINT = getattr(args, "fingerprint", False)

    if args.command == "get-cacert":
        get_ca_cert_pem()
        print(f"{Color.GREEN.value}✓ cacert.pem downloaded to {SHARE_PATH / 'cacert.pem'}")
        return 0

    if args.command == "host-check":
        try:
            hostname, port = get_hostname_and_port(args.target)
            certificate = get_certificate_from_hostname_and_port(hostname, port, timeout=args.timeout)
            certificate_manager = CertStore(SHARE_PATH / "cacert.pem", args.max_depth, hostname=hostname)
            certificate_manager.start_chain_traversal(certificate)
            status_print(f"{Color.GREEN.value}✓ Certificate chain verification complete!")

            if args.expect_fail:
                print(f"{Color.RED.value}ERROR: Expected failure but verification succeeded", file=sys.stderr)
                return 1
            # Only emit the fingerprint once verification has fully succeeded, so a hash on stdout is trustworthy.
            if args.fingerprint:
                print(certificate.fingerprint(hashes.SHA256()).hex())
            return 0
        except CryptoCliNetworkException:
            raise  # No verdict was reached: never counts as an expected verification failure
        except CryptoCliException as e:
            if args.expect_fail:
                vprint(f"Verification failed as expected: {e}")
                status_print(f"{Color.GREEN.value}✓ Failed as expected")
                return 0
            else:
                raise  # Re-raise to be caught by main exception handler

    return 1  # Should never reach here, but return error if we do


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n  !!  KeyboardInterrupt received  !!  \n")
        exit(130)  # Standard exit code for SIGINT
    except CryptoCliException as e:
        status_print(f"{Color.RED.value}\n  !!  {e}  !!  \n")
        exit(1)  # General error
    except Exception:
        raise
