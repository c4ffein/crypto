#!/usr/bin/env python3
"""
Security-focused unit tests for certificate verification logic.
These tests specifically check for vulnerabilities in certificate chain validation.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto import CertStore, CryptoCliException


class TestSubjectNameMatchingSecurity(unittest.TestCase):
    """
    Test that the subject name matching fallback properly validates signatures.

    This tests for a vulnerability where an attacker could create a fake intermediate
    certificate with a subject matching a trusted root CA, without actually being
    signed by that root.
    """

    @classmethod
    def setUpClass(cls):
        """Generate test certificates"""
        # Generate a real trusted root CA
        cls.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            ]
        )

        cls.root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)  # Self-signed
            .public_key(cls.root_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(cls.root_key.public_key()),
                critical=False,
            )
            .sign(cls.root_key, hashes.SHA256())
        )

        # Generate an attacker's key (different from root)
        cls.attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create a fake intermediate with the SAME subject as the root
        # but signed by the attacker's key (not the real root)
        fake_intermediate_subject = root_subject  # Same subject as root!

        cls.fake_intermediate = (
            x509.CertificateBuilder()
            .subject_name(fake_intermediate_subject)
            .issuer_name(fake_intermediate_subject)  # Claims to be issued by root
            .public_key(cls.attacker_key.public_key())  # But has attacker's public key
            .serial_number(2)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(cls.root_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(cls.attacker_key.public_key()),
                critical=False,
            )
            .sign(cls.attacker_key, hashes.SHA256())  # Self-signed by attacker!
        )

        # Create a temporary cacert file with only our test root
        cls.test_cacert_path = Path(__file__).parent / "test_cacert.pem"
        with open(cls.test_cacert_path, "w") as f:
            f.write("Test Root CA\n")
            f.write("=" * 70 + "\n")
            f.write(cls.root_cert.public_bytes(serialization.Encoding.PEM).decode())

    @classmethod
    def tearDownClass(cls):
        """Clean up test files"""
        if cls.test_cacert_path.exists():
            cls.test_cacert_path.unlink()

    def test_fake_intermediate_with_matching_subject_is_rejected(self):
        """
        Test that a fake intermediate certificate with a subject matching a trusted root
        is rejected if it wasn't actually signed by that root.

        Attack scenario:
        1. Attacker creates intermediate with subject="CN=Test Root CA"
        2. Attacker signs it with their own key (not the real root's key)
        3. Subject name matches the real root in cacerts
        4. Without signature verification, this would be accepted
        5. With proper verification, this should be rejected
        """
        cert_store = CertStore(str(self.test_cacert_path), max_chain_depth=4)

        # This should raise an exception because the fake intermediate
        # was not actually signed by the trusted root
        with self.assertRaises(CryptoCliException) as context:
            cert_store.chain_traversal_step(self.fake_intermediate, depth=1)

        # Should fail because signature verification fails
        # (either "Certificate signature verification failed" or "Root CA not found")
        error_msg = str(context.exception)
        self.assertTrue(
            "Certificate signature verification failed" in error_msg or "Root CA not found" in error_msg,
            f"Expected signature verification or root CA error, got: {error_msg}",
        )

    def test_legitimate_cross_signed_intermediate_is_accepted(self):
        """
        Test that a legitimate cross-signed intermediate (actually signed by the root)
        is correctly accepted.
        """
        # Create a legitimate intermediate signed by the real root
        intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create intermediate with same subject as root (cross-signed case)
        intermediate_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            ]
        )

        legitimate_intermediate = (
            x509.CertificateBuilder()
            .subject_name(intermediate_subject)
            .issuer_name(self.root_cert.subject)  # Issued by root
            .public_key(intermediate_key.public_key())
            .serial_number(3)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
                critical=False,
            )
            .sign(self.root_key, hashes.SHA256())  # ACTUALLY signed by the root
        )

        cert_store = CertStore(str(self.test_cacert_path), max_chain_depth=4)

        # This should succeed because it's genuinely signed by the trusted root
        try:
            cert_store.chain_traversal_step(legitimate_intermediate, depth=1)
            # If we get here, verification succeeded (as it should)
        except CryptoCliException as e:
            self.fail(f"Legitimate cross-signed intermediate was rejected: {e}")


class TestPublicKeyMatchingSecurity(unittest.TestCase):
    """
    Test that the public key matching fallback properly validates signatures.

    This tests for a vulnerability where an attacker could create a fake intermediate
    certificate with a PUBLIC KEY copied from a trusted root CA, without actually being
    signed by anyone who controls that private key.
    """

    @classmethod
    def setUpClass(cls):
        """Generate test certificates"""
        # Generate a real trusted root CA
        cls.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            ]
        )

        cls.root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)  # Self-signed
            .public_key(cls.root_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(cls.root_key.public_key()),
                critical=False,
            )
            .sign(cls.root_key, hashes.SHA256())
        )

        # Generate an attacker's key (different from root)
        cls.attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create a fake intermediate with the SAME PUBLIC KEY as the root
        # but signed by the attacker's key (not the real root's key)
        # This is the CRITICAL difference from the subject-matching test above
        fake_intermediate_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Evil Intermediate CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil Org"),
            ]
        )

        cls.fake_intermediate_with_copied_pubkey = (
            x509.CertificateBuilder()
            .subject_name(fake_intermediate_subject)  # Different subject (not matching root)
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Issuer")]))
            .public_key(cls.root_key.public_key())  # ← COPIED public key from root!
            .serial_number(2)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                # AKI that doesn't match the root's SKI (to avoid SKI/AKI matching path)
                x509.AuthorityKeyIdentifier.from_issuer_public_key(cls.attacker_key.public_key()),
                critical=False,
            )
            .add_extension(
                # SKI based on the copied public key
                x509.SubjectKeyIdentifier.from_public_key(cls.root_key.public_key()),
                critical=False,
            )
            .sign(cls.attacker_key, hashes.SHA256())  # Signed by attacker, not root!
        )

        # Create a temporary cacert file with only our test root
        cls.test_cacert_path = Path(__file__).parent / "test_pubkey_cacert.pem"
        with open(cls.test_cacert_path, "w") as f:
            f.write("Test Root CA\n")
            f.write("=" * 70 + "\n")
            f.write(cls.root_cert.public_bytes(serialization.Encoding.PEM).decode())

    @classmethod
    def tearDownClass(cls):
        """Clean up test files"""
        if cls.test_cacert_path.exists():
            cls.test_cacert_path.unlink()

    def test_public_key_matching_accepts_cert_when_called_directly(self):
        """
        Test that demonstrates the public key matching logic WILL accept a certificate
        with a copied public key when chain_traversal_step() is called directly.

        IMPORTANT: This is NOT a vulnerability in normal use because:
        1. All certificates reach chain_traversal_step() through validated paths:
           - Leaf certs: TLS handshake proves server has private key
           - Intermediates: Line 391 verifies signature before recursion
        2. This test bypasses normal flow by calling chain_traversal_step() directly

        WHY THIS TEST EXISTS:
        - Documents that chain_traversal_step() expects pre-validated certificates
        - Ensures anyone using CertStore as a library understands the contract
        - Prevents regression if the validation flow changes
        - Tests defense-in-depth: the logic itself doesn't re-verify

        This test will SUCCEED (no exception) because public key matching
        is a valid optimization for cross-signed certificates when the cert
        has already been validated through the signature chain.
        """
        cert_store = CertStore(str(self.test_cacert_path), max_chain_depth=4)

        # When called directly (bypassing normal validation), this succeeds
        # because public key matches a trusted root
        try:
            cert_store.chain_traversal_step(self.fake_intermediate_with_copied_pubkey, depth=1)
            # Success expected - public key matching works
        except CryptoCliException as e:
            self.fail(
                f"Public key matching should accept cert when called directly. "
                f"This indicates the logic changed. Error: {e}"
            )

    def test_stolen_public_key_cannot_forge_valid_chain(self):
        """
        Test that proves the REAL protection: an attacker cannot use a certificate
        with a stolen public key to create a valid certificate chain.

        This is the actual security guarantee:
        - Even if attacker copies a public key from a trusted root
        - They can't use it to sign child certificates
        - Because they don't have the corresponding private key
        - Signature verification will fail

        Attack scenario:
        1. Attacker wants to issue a cert for evil.com
        2. Creates a fake intermediate with DigiCert's public key (stolen)
        3. Signs it with their own private key
        4. Creates leaf cert for evil.com
        5. Signs leaf with their own private key (not DigiCert's)
        6. Tries to verify: leaf -> fake intermediate -> real root

        Result: Signature verification fails because leaf signature cannot be
        verified with the fake intermediate's public key.
        """
        # Create a leaf certificate (for evil.com)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.com")])

        # Sign the leaf with attacker's key (not the root's key that we copied)
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "Evil Intermediate CA"),
                    ]
                )
            )
            .public_key(leaf_key.public_key())
            .serial_number(100)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("evil.com")]),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.attacker_key.public_key()),
                critical=False,
            )
            .sign(self.attacker_key, hashes.SHA256())  # Signed by attacker
        )

        # Try to verify the leaf was signed by the fake intermediate
        # The fake intermediate has the root's PUBLIC key but was signed by attacker
        # This MUST fail because:
        # - leaf_cert.signature was created with attacker_key
        # - fake_intermediate.public_key() is root_key.public_key()
        # - These don't match!

        from crypto import verify_certificate_signature

        with self.assertRaises(CryptoCliException) as context:
            verify_certificate_signature(leaf_cert, self.fake_intermediate_with_copied_pubkey)

        # Should fail with signature verification error
        self.assertIn(
            "Certificate signature verification failed",
            str(context.exception),
            "Expected signature verification to fail when using cert with stolen public key",
        )

    def test_leaf_certificate_with_copied_public_key_at_depth_zero(self):
        """
        Test that a leaf certificate (depth=0) with a public key matching a trusted root
        should ideally be rejected by the verification logic.

        DEFENSE-IN-DEPTH concern:
        - TLS handshake protects against this (attacker can't complete handshake without private key)
        - However, the verification logic should ALSO reject this scenario
        - Leaf certificates should NEVER have the same public key as a root CA

        Why this matters:
        1. Defense-in-depth: don't rely solely on TLS handshake protection
        2. Library usage: protects users who call chain_traversal_step() directly
        3. Suspicious behavior that shouldn't be normalized

        PROPOSED FIX: Restrict public key matching to depth > 0 only.

        Currently, this test will PASS (cert accepted) at depth=0.
        After fix, it should FAIL (cert rejected) with a depth-related error.
        """
        # Create a "leaf" certificate with public key matching the root
        leaf_with_root_pubkey = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.com")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Issuer")]))
            .public_key(self.root_key.public_key())  # COPIED public key from root!
            .serial_number(999)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("evil.com")]),
                critical=False,
            )
            .add_extension(
                # AKI that doesn't match the root's SKI (to avoid SKI/AKI matching path)
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.attacker_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.root_key.public_key()),
                critical=False,
            )
            .sign(self.attacker_key, hashes.SHA256())  # Signed by attacker
        )

        cert_store = CertStore(str(self.test_cacert_path), max_chain_depth=4)

        # This should now FAIL with the depth check in place
        with self.assertRaises(CryptoCliException) as context:
            cert_store.chain_traversal_step(leaf_with_root_pubkey, depth=0)

        # Verify the error message mentions leaf certificates
        error_msg = str(context.exception)
        self.assertTrue(
            "leaf" in error_msg.lower() or "depth" in error_msg.lower(),
            f"Expected leaf/depth-related error, got: {error_msg}",
        )


class TestCompleteValidChain(unittest.TestCase):
    """
    Test a complete, valid certificate chain: leaf -> intermediate -> root

    This test creates and verifies a realistic three-level certificate chain:
    - Root CA (self-signed, in cacert.pem)
    - Intermediate CA (signed by root)
    - Leaf certificate (signed by intermediate, for example.com)

    All signatures are valid and the chain should verify successfully.
    """

    @classmethod
    def setUpClass(cls):
        """Generate a complete valid certificate chain"""
        # Step 1: Generate Root CA
        cls.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ]
        )

        cls.root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)  # Self-signed
            .public_key(cls.root_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  # 10 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=2),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(cls.root_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(cls.root_key, hashes.SHA256())
        )

        # Step 2: Generate Intermediate CA
        cls.intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        intermediate_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ]
        )

        cls.intermediate_cert = (
            x509.CertificateBuilder()
            .subject_name(intermediate_subject)
            .issuer_name(root_subject)  # Issued by root
            .public_key(cls.intermediate_key.public_key())
            .serial_number(2)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1825))  # 5 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(cls.intermediate_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(cls.root_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(cls.root_key, hashes.SHA256())  # Signed by root
        )

        # Step 3: Generate Leaf Certificate
        cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ]
        )

        cls.leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(intermediate_subject)  # Issued by intermediate
            .public_key(cls.leaf_key.public_key())
            .serial_number(3)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))  # 90 days
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("example.com"),
                        x509.DNSName("www.example.com"),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(cls.leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(cls.intermediate_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(cls.intermediate_key, hashes.SHA256())  # Signed by intermediate
        )

        # Create a temporary cacert file with only our test root
        cls.test_cacert_path = Path(__file__).parent / "test_complete_chain_cacert.pem"
        with open(cls.test_cacert_path, "w") as f:
            f.write("Test Root CA\n")
            f.write("=" * 70 + "\n")
            f.write(cls.root_cert.public_bytes(serialization.Encoding.PEM).decode())

    @classmethod
    def tearDownClass(cls):
        """Clean up test files"""
        if cls.test_cacert_path.exists():
            cls.test_cacert_path.unlink()

    def test_complete_valid_chain_verifies(self):
        """
        Test that a complete valid chain (leaf -> intermediate -> root) verifies successfully.

        This simulates the real-world scenario where:
        1. A website presents its leaf certificate
        2. The chain traversal verifies the leaf was signed by the intermediate
        3. The traversal continues and verifies the intermediate was signed by the root
        4. The root is found in the trusted CA bundle
        5. All signatures are verified
        """
        from crypto import verify_certificate_signature

        # First, manually verify each link in the chain
        # Leaf signed by intermediate
        verify_certificate_signature(self.leaf_cert, self.intermediate_cert)

        # Intermediate signed by root
        verify_certificate_signature(self.intermediate_cert, self.root_cert)

        # Root self-signed
        verify_certificate_signature(self.root_cert, self.root_cert)

        # Now test the full chain traversal
        # We'll mock the AIA fetch by temporarily monkeypatching
        import crypto

        original_get_cert_from_url = crypto.get_certificate_from_url

        def mock_get_certificate_from_url(url):
            # Return intermediate cert when AIA is accessed
            return self.intermediate_cert

        try:
            crypto.get_certificate_from_url = mock_get_certificate_from_url

            # Add AIA extension to leaf cert pointing to intermediate
            # (We need to rebuild the cert with AIA)
            leaf_with_aia = (
                x509.CertificateBuilder()
                .subject_name(self.leaf_cert.subject)
                .issuer_name(self.leaf_cert.issuer)
                .public_key(self.leaf_key.public_key())
                .serial_number(4)
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.SubjectAlternativeName(
                        [
                            x509.DNSName("example.com"),
                            x509.DNSName("www.example.com"),
                        ]
                    ),
                    critical=False,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(self.leaf_key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(self.intermediate_key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityInformationAccess(
                        [
                            x509.AccessDescription(
                                access_method=x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                                access_location=x509.UniformResourceIdentifier(
                                    "http://ca.example.com/intermediate.crt"
                                ),
                            ),
                        ]
                    ),
                    critical=False,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(self.intermediate_key, hashes.SHA256())
            )

            # Add AIA extension to intermediate pointing to root
            def mock_get_cert_based_on_call(url):
                if "intermediate" in url:
                    # Return an intermediate with AIA pointing to root
                    intermediate_with_aia = (
                        x509.CertificateBuilder()
                        .subject_name(self.intermediate_cert.subject)
                        .issuer_name(self.intermediate_cert.issuer)
                        .public_key(self.intermediate_key.public_key())
                        .serial_number(5)
                        .not_valid_before(datetime.now(timezone.utc))
                        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1825))
                        .add_extension(
                            x509.BasicConstraints(ca=True, path_length=0),
                            critical=True,
                        )
                        .add_extension(
                            x509.SubjectKeyIdentifier.from_public_key(self.intermediate_key.public_key()),
                            critical=False,
                        )
                        .add_extension(
                            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()),
                            critical=False,
                        )
                        .add_extension(
                            x509.AuthorityInformationAccess(
                                [
                                    x509.AccessDescription(
                                        access_method=x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                                        access_location=x509.UniformResourceIdentifier(
                                            "http://ca.example.com/root.crt"
                                        ),
                                    ),
                                ]
                            ),
                            critical=False,
                        )
                        .add_extension(
                            x509.KeyUsage(
                                digital_signature=True,
                                key_cert_sign=True,
                                crl_sign=True,
                                key_encipherment=False,
                                content_commitment=False,
                                data_encipherment=False,
                                key_agreement=False,
                                encipher_only=False,
                                decipher_only=False,
                            ),
                            critical=True,
                        )
                        .sign(self.root_key, hashes.SHA256())
                    )
                    return intermediate_with_aia
                return self.root_cert

            crypto.get_certificate_from_url = mock_get_cert_based_on_call

            # Create cert store and verify the chain
            cert_store = crypto.CertStore(str(self.test_cacert_path), max_chain_depth=6, hostname="example.com")

            # This should succeed without raising any exceptions
            cert_store.start_chain_traversal(leaf_with_aia)

        finally:
            # Restore original function
            crypto.get_certificate_from_url = original_get_cert_from_url


class TestChainSignatureFailure(unittest.TestCase):
    """
    Test that certificate chain verification fails when signatures are invalid.

    This test creates chains where the cryptographic signatures don't match,
    simulating various attack scenarios where an attacker tries to forge certificates.
    """

    @classmethod
    def setUpClass(cls):
        """Generate certificates for testing signature failures"""
        # Generate a legitimate root CA
        cls.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Legitimate Root CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Trusted Org"),
            ]
        )

        cls.root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)
            .public_key(cls.root_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(cls.root_key.public_key()),
                critical=False,
            )
            .sign(cls.root_key, hashes.SHA256())
        )

        # Generate attacker's key
        cls.attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create an intermediate that CLAIMS to be signed by the root
        # but is actually signed by the attacker
        intermediate_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Fake Intermediate CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Attacker Org"),
            ]
        )

        cls.fake_intermediate = (
            x509.CertificateBuilder()
            .subject_name(intermediate_subject)
            .issuer_name(root_subject)  # Claims to be issued by legitimate root
            .public_key(cls.attacker_key.public_key())
            .serial_number(2)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1825))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(cls.attacker_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(cls.root_key.public_key()),
                critical=False,
            )
            .sign(cls.attacker_key, hashes.SHA256())  # Signed by attacker, NOT root!
        )

        # Create a leaf cert signed by the attacker
        cls.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.com")])

        cls.leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(intermediate_subject)
            .public_key(cls.leaf_key.public_key())
            .serial_number(3)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("evil.com")]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(cls.leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(cls.attacker_key.public_key()),
                critical=False,
            )
            .sign(cls.attacker_key, hashes.SHA256())  # Signed by attacker
        )

        # Create temporary cacert file
        cls.test_cacert_path = Path(__file__).parent / "test_signature_fail_cacert.pem"
        with open(cls.test_cacert_path, "w") as f:
            f.write("Legitimate Root CA\n")
            f.write("=" * 70 + "\n")
            f.write(cls.root_cert.public_bytes(serialization.Encoding.PEM).decode())

    @classmethod
    def tearDownClass(cls):
        """Clean up test files"""
        if cls.test_cacert_path.exists():
            cls.test_cacert_path.unlink()

    def test_intermediate_with_invalid_signature_is_rejected(self):
        """
        Test that an intermediate with an invalid signature is rejected.

        Attack scenario:
        1. Attacker creates intermediate claiming to be issued by "Legitimate Root CA"
        2. Attacker signs it with their own key (not the root's key)
        3. Certificate chain verification should fail when checking the signature
        """
        from crypto import verify_certificate_signature

        # Direct signature verification should fail
        with self.assertRaises(CryptoCliException) as context:
            verify_certificate_signature(self.fake_intermediate, self.root_cert)

        self.assertIn(
            "Certificate signature verification failed",
            str(context.exception),
            "Expected signature verification to fail for fake intermediate",
        )

    def test_chain_with_forged_intermediate_fails(self):
        """
        Test that a complete chain with a forged intermediate certificate fails verification.

        Chain structure:
        - Leaf (evil.com) <- signed by attacker_key
        - Fake Intermediate (claims issuer=Legitimate Root) <- signed by attacker_key
        - Legitimate Root <- properly self-signed

        The verification should fail when trying to verify the fake intermediate's signature.
        """
        from crypto import verify_certificate_signature

        # Test 1: Leaf -> Fake Intermediate (this should succeed because attacker signed both)
        try:
            verify_certificate_signature(self.leaf_cert, self.fake_intermediate)
            # This succeeds because the attacker consistently used their key
        except CryptoCliException:
            self.fail("Leaf verification against fake intermediate should succeed (same key)")

        # Test 2: Fake Intermediate -> Root (this should FAIL)
        with self.assertRaises(CryptoCliException) as context:
            verify_certificate_signature(self.fake_intermediate, self.root_cert)

        self.assertIn(
            "Certificate signature verification failed",
            str(context.exception),
            "Expected signature verification to fail when verifying fake intermediate against real root",
        )

    def test_chain_traversal_rejects_forged_chain(self):
        """
        Test that the full chain traversal correctly rejects a forged chain.

        This tests the complete verification flow including hostname verification.
        """
        import crypto

        original_get_cert_from_url = crypto.get_certificate_from_url

        # Mock AIA fetching to return our fake intermediate
        def mock_get_certificate_from_url(url):
            return self.fake_intermediate

        try:
            crypto.get_certificate_from_url = mock_get_certificate_from_url

            # Add AIA extension to leaf
            leaf_with_aia = (
                x509.CertificateBuilder()
                .subject_name(self.leaf_cert.subject)
                .issuer_name(self.leaf_cert.issuer)
                .public_key(self.leaf_key.public_key())
                .serial_number(4)
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("evil.com")]),
                    critical=False,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(self.leaf_key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(self.attacker_key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityInformationAccess(
                        [
                            x509.AccessDescription(
                                access_method=x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                                access_location=x509.UniformResourceIdentifier("http://evil.com/intermediate.crt"),
                            ),
                        ]
                    ),
                    critical=False,
                )
                .sign(self.attacker_key, hashes.SHA256())
            )

            cert_store = crypto.CertStore(str(self.test_cacert_path), max_chain_depth=6, hostname="evil.com")

            # This should raise an exception due to signature verification failure
            with self.assertRaises(CryptoCliException) as context:
                cert_store.start_chain_traversal(leaf_with_aia)

            error_msg = str(context.exception)
            self.assertTrue(
                "Certificate signature verification failed" in error_msg or "Root CA not found" in error_msg,
                f"Expected signature verification failure, got: {error_msg}",
            )

        finally:
            crypto.get_certificate_from_url = original_get_cert_from_url


if __name__ == "__main__":
    unittest.main()
