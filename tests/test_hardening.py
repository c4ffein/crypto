#!/usr/bin/env python3
"""
Regression tests for verifier gaps and robustness issues:
issuer constraints, root validity, EdDSA, cacert.pem parsing, redirect validation.
Everything here is offline: certificates are generated locally and HTTP goes to a loopback server.
"""

import os
import sys
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

sys.path.insert(0, str(Path(__file__).parent.parent))

import crypto
from crypto import CertStore, CryptoCliException


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def make_cert(
    subject,
    issuer,
    key,
    signing_key,
    *,
    ca=None,
    path_length=None,
    key_cert_sign=None,
    aki_key=None,
    aia=None,
    san=None,
    not_before=None,
    not_after=None,
):
    """Build a certificate. ca=None means no basicConstraints, key_cert_sign=None means no keyUsage."""
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=30))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if key_cert_sign is not None:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=key_cert_sign,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if aki_key is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(aki_key.public_key()), critical=False
        )
    if aia is not None:
        access = x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))
        builder = builder.add_extension(x509.AuthorityInformationAccess([access]), critical=False)
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    is_eddsa = isinstance(signing_key, ed25519.Ed25519PrivateKey)
    return builder.sign(signing_key, None if is_eddsa else hashes.SHA256())


def write_bundle(path, certs, comment_line=True):
    """Write a cacert.pem in the curl.se layout; comment_line adds the '# Fingerprint' line of newer bundles."""
    with Path(path).open("w", encoding="utf-8") as file:
        file.write("##\n## Bundle of CA Root Certificates\n##\n\n")
        for name, cert in certs.items():
            file.write(f"\n{name}\n{'=' * len(name)}\n")
            if comment_line:
                file.write("# Fingerprint (SHA-256): " + cert.fingerprint(hashes.SHA256()).hex(":").upper() + "\n")
            file.write(cert.public_bytes(serialization.Encoding.PEM).decode())


class ChainTestCase(unittest.TestCase):
    """Common setup: a trusted root in a temporary cacert.pem, and AIA fetches served from a dict."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bundle = Path(self.tmp.name) / "cacert.pem"
        self.root_key = new_key()
        self.root = make_cert("Test Root", "Test Root", self.root_key, self.root_key, ca=True, key_cert_sign=True)
        write_bundle(self.bundle, {"Test Root": self.root})

    def traverse(self, leaf, hostname, issuers_by_url=None, max_chain_depth=4):
        issuers_by_url = issuers_by_url or {}
        store = CertStore(str(self.bundle), max_chain_depth=max_chain_depth, hostname=hostname)
        with mock.patch.object(crypto, "get_certificate_from_url", lambda url: issuers_by_url[url]):
            store.start_chain_traversal(leaf)


class TestIssuerConstraints(ChainTestCase):
    """A certificate may only act as an issuer if it is a CA allowed to sign at that position."""

    URL = "http://aia.test/issuer.crt"

    def chain_with_issuer(self, **issuer_kwargs):
        """root -> issuer (built with issuer_kwargs) -> leaf for victim.test"""
        issuer_key, leaf_key = new_key(), new_key()
        issuer = make_cert(
            "issuer.test", "Test Root", issuer_key, self.root_key, aki_key=self.root_key, **issuer_kwargs
        )
        leaf = make_cert(
            "victim.test",
            "issuer.test",
            leaf_key,
            issuer_key,
            ca=False,
            aki_key=issuer_key,
            aia=self.URL,
            san="victim.test",
        )
        return leaf, {self.URL: issuer}

    def test_ca_issuer_is_accepted(self):
        leaf, issuers = self.chain_with_issuer(ca=True, key_cert_sign=True)
        self.traverse(leaf, "victim.test", issuers)

    def test_leaf_certificate_acting_as_issuer_is_rejected(self):
        """The holder of any valid leaf certificate must not be able to issue for another hostname"""
        leaf, issuers = self.chain_with_issuer(ca=False, san="evil.test")
        with self.assertRaisesRegex(CryptoCliException, "not a CA"):
            self.traverse(leaf, "victim.test", issuers)

    def test_issuer_without_basic_constraints_is_rejected(self):
        leaf, issuers = self.chain_with_issuer()
        with self.assertRaisesRegex(CryptoCliException, "not a CA"):
            self.traverse(leaf, "victim.test", issuers)

    def test_issuer_without_key_cert_sign_is_rejected(self):
        leaf, issuers = self.chain_with_issuer(ca=True, key_cert_sign=False)
        with self.assertRaisesRegex(CryptoCliException, "keyUsage"):
            self.traverse(leaf, "victim.test", issuers)

    def chain_with_two_intermediates(self, upper_path_length):
        """root -> upper (pathLen=upper_path_length) -> lower -> leaf"""
        upper_key, lower_key, leaf_key = new_key(), new_key(), new_key()
        upper = make_cert(
            "upper.test",
            "Test Root",
            upper_key,
            self.root_key,
            ca=True,
            path_length=upper_path_length,
            aki_key=self.root_key,
        )
        lower = make_cert(
            "lower.test",
            "upper.test",
            lower_key,
            upper_key,
            ca=True,
            aki_key=upper_key,
            aia="http://aia.test/upper.crt",
        )
        leaf = make_cert(
            "victim.test",
            "lower.test",
            leaf_key,
            lower_key,
            ca=False,
            aki_key=lower_key,
            aia="http://aia.test/lower.crt",
            san="victim.test",
        )
        return leaf, {"http://aia.test/upper.crt": upper, "http://aia.test/lower.crt": lower}

    def test_path_length_constraint_is_enforced(self):
        """pathLen=0 allows signing leaf certificates only, not a further intermediate"""
        leaf, issuers = self.chain_with_two_intermediates(upper_path_length=0)
        with self.assertRaisesRegex(CryptoCliException, "path length"):
            self.traverse(leaf, "victim.test", issuers)

    def test_path_length_constraint_allows_a_chain_within_the_limit(self):
        leaf, issuers = self.chain_with_two_intermediates(upper_path_length=1)
        self.traverse(leaf, "victim.test", issuers)


class TestRootValidity(ChainTestCase):
    def test_expired_root_matched_by_key_identifier_is_rejected(self):
        now = datetime.now(UTC)
        old_key, leaf_key = new_key(), new_key()
        expired_root = make_cert(
            "Old Root",
            "Old Root",
            old_key,
            old_key,
            ca=True,
            not_before=now - timedelta(days=900),
            not_after=now - timedelta(days=30),
        )
        write_bundle(self.bundle, {"Old Root": expired_root})
        leaf = make_cert("a.test", "Old Root", leaf_key, old_key, ca=False, aki_key=old_key, san="a.test")
        with self.assertRaisesRegex(CryptoCliException, "expired"):
            self.traverse(leaf, "a.test")

    def test_valid_root_matched_by_key_identifier_is_accepted(self):
        leaf_key = new_key()
        leaf = make_cert("a.test", "Test Root", leaf_key, self.root_key, ca=False, aki_key=self.root_key, san="a.test")
        self.traverse(leaf, "a.test")


class TestEdDSA(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.ed_key = ed25519.Ed25519PrivateKey.generate()
        self.ed_root = make_cert("Ed Root", "Ed Root", self.ed_key, self.ed_key, ca=True)
        self.leaf = make_cert("a.test", "Ed Root", new_key(), self.ed_key, ca=False, aki_key=self.ed_key, san="a.test")

    def test_ed25519_signature_verifies(self):
        crypto.verify_certificate_signature(self.leaf, self.ed_root)
        crypto.verify_certificate_signature(self.ed_root, self.ed_root)

    def test_ed25519_signature_from_another_key_is_rejected(self):
        other_key = ed25519.Ed25519PrivateKey.generate()
        other_root = make_cert("Ed Root", "Ed Root", other_key, other_key, ca=True)
        with self.assertRaisesRegex(CryptoCliException, "Certificate signature verification failed"):
            crypto.verify_certificate_signature(self.leaf, other_root)

    def test_chain_to_ed25519_root_verifies(self):
        write_bundle(self.bundle, {"Ed Root": self.ed_root})
        self.traverse(self.leaf, "a.test")


class TestCacertParsing(ChainTestCase):
    def test_layout_without_comment_line(self):
        write_bundle(self.bundle, {"Test Root": self.root}, comment_line=False)
        self.assertEqual(crypto.load_cacerts(str(self.bundle)), {"Test Root": self.root})

    def test_layout_with_fingerprint_comment_line(self):
        """curl.se bundles now carry a '# Fingerprint' line between the underline and BEGIN CERTIFICATE"""
        other_key = new_key()
        other = make_cert("Other Root", "Other Root", other_key, other_key, ca=True)
        write_bundle(self.bundle, {"Test Root": self.root, "Other Root": other})
        self.assertEqual(crypto.load_cacerts(str(self.bundle)), {"Test Root": self.root, "Other Root": other})

    def assert_unparseable(self, content):
        self.bundle.write_text(content, encoding="utf-8")
        with self.assertRaisesRegex(CryptoCliException, "could not be parsed"):
            crypto.load_cacerts(str(self.bundle))

    def test_empty_file(self):
        self.assert_unparseable("")

    def test_file_without_certificates(self):
        self.assert_unparseable("##\n## Bundle of CA Root Certificates\n##\n")

    def test_certificate_without_name_and_underline(self):
        self.assert_unparseable(self.root.public_bytes(serialization.Encoding.PEM).decode())

    def test_corrupted_certificate_body(self):
        corrupted = "Name\n====\n-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n"
        self.assert_unparseable(corrupted)

    def test_root_that_cannot_be_loaded_is_skipped(self):
        """One root the library refuses must not cost all the others"""
        write_bundle(self.bundle, {"Test Root": self.root})
        with self.bundle.open("a", encoding="utf-8") as file:
            file.write("\nBroken Root\n===========\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
        self.assertEqual(crypto.load_cacerts(str(self.bundle)), {"Test Root": self.root})

    def test_missing_file(self):
        with self.assertRaisesRegex(CryptoCliException, "not found"):
            crypto.load_cacerts(str(Path(self.tmp.name) / "absent.pem"))


class RedirectingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/private")
            self.end_headers()
        elif self.path == "/to-https":
            self.send_response(302)
            self.send_header("Location", "https://127.0.0.1:1/")
            self.end_headers()
        else:
            body = b"secret" if self.path == "/private" else b"data"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestRedirectValidation(unittest.TestCase):
    """urllib follows redirects by itself: every hop must go through the same validation as the first URL."""

    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectingHandler)
        self.server.hits = []
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        no_proxy = mock.patch.dict(os.environ, {"no_proxy": "*", "NO_PROXY": "*"})
        no_proxy.start()
        self.addCleanup(no_proxy.stop)

    @staticmethod
    def refuse_private(url):
        if url.endswith("/private"):
            raise CryptoCliException(f"refused: {url}")

    def test_redirect_is_followed_without_validator(self):
        self.assertEqual(crypto.get_bytes_from_url(f"{self.base}/redirect"), b"secret")

    def test_redirect_target_is_validated_before_being_fetched(self):
        with self.assertRaisesRegex(CryptoCliException, "refused"):
            crypto.get_bytes_from_url(f"{self.base}/redirect", validate_url=self.refuse_private)
        self.assertEqual(self.server.hits, ["/redirect"])

    def test_initial_url_is_validated_before_being_fetched(self):
        with self.assertRaisesRegex(CryptoCliException, "refused"):
            crypto.get_bytes_from_url(f"{self.base}/private", validate_url=self.refuse_private)
        self.assertEqual(self.server.hits, [])

    def test_redirect_to_another_scheme_is_refused(self):
        with self.assertRaisesRegex(CryptoCliException, "different scheme"):
            crypto.get_bytes_from_url(f"{self.base}/to-https")

    def test_aia_fetch_validates_redirect_targets(self):
        with mock.patch.object(crypto, "validate_aia_url", self.refuse_private):
            with self.assertRaisesRegex(CryptoCliException, "refused"):
                crypto.get_certificate_from_url(f"{self.base}/redirect")
        self.assertEqual(self.server.hits, ["/redirect"])

    def test_aia_fetch_refuses_loopback(self):
        with self.assertRaisesRegex(CryptoCliException, "non-global"):
            crypto.get_certificate_from_url(f"{self.base}/ok")
        self.assertEqual(self.server.hits, [])

    def test_aia_response_that_is_not_a_certificate_is_a_clean_error(self):
        with mock.patch.object(crypto, "validate_aia_url", lambda url: None):
            with self.assertRaisesRegex(CryptoCliException, "did not return a DER certificate"):
                crypto.get_certificate_from_url(f"{self.base}/ok")


if __name__ == "__main__":
    unittest.main()
