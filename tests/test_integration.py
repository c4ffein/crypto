#!/usr/bin/env python3
"""
Integration tests for crypto CLI tool
Tests against real servers to verify certificate chain validation
"""

import subprocess
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class TestCase:
    name: str
    host: str
    expect_fail: bool = False
    max_depth: Optional[int] = None


# Find crypto.py relative to this test file
CRYPTO_CLI = Path(__file__).parent.parent / "crypto.py"

# Test cases
TEST_CASES = [
    # Google Services (non-standard ports)
    TestCase("gmail_smtp", "smtp.gmail.com:465"),
    TestCase("gmail_imap", "imap.gmail.com:993"),
    # Services you use (dogfooding)
    TestCase("anthropic_api", "api.anthropic.com"),
    TestCase("qonto_thirdparty", "thirdparty.qonto.com"),
    # AWS services - chain includes trusted root (short-circuits before expired cross-signed cert)
    TestCase("aws", "aws.amazon.com"),
    TestCase("aws_s3", "s3.us-west-2.amazonaws.com"),
    # Popular services (CA diversity)
    TestCase("github", "github.com"),
    TestCase("cloudflare", "cloudflare.com"),
    TestCase("letsencrypt", "letsencrypt.org"),
    TestCase("eff", "www.eff.org"),
    TestCase("badssl", "badssl.com"),
    # === badssl.com Test Suite - Valid Certificates ===
    # Signature algorithms
    TestCase("badssl_sha256", "sha256.badssl.com"),
    # Note: sha384/sha512 fail at TLS handshake level (Python's SSL rejects them before we can verify)
    # ECC key types
    TestCase("badssl_ecc256", "ecc256.badssl.com"),
    TestCase("badssl_ecc384", "ecc384.badssl.com"),
    # RSA key sizes
    TestCase("badssl_rsa2048", "rsa2048.badssl.com"),
    TestCase("badssl_rsa4096", "rsa4096.badssl.com"),
    # Note: rsa8192 fails at TLS handshake (rejected 8192-bit keys, won't investigate for now)
    # Extended validation
    # Note: extended-validation fails at TLS handshake (cert complexity issue)
    # Subject Alternative Names (SANs)
    # Note: 1000-sans and 10000-sans fail at TLS handshake (cert size too large)
    # Long domain names
    TestCase("badssl_long_subdomain", "long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com"),
    TestCase("badssl_long_no_dashes", "longextendedsubdomainnamewithoutdashesinordertotestwordwrapping.badssl.com"),
    # Mozilla cipher suites (these test TLS config, but certs should be valid)
    TestCase("badssl_mozilla_modern", "mozilla-modern.badssl.com"),
    TestCase("badssl_mozilla_intermediate", "mozilla-intermediate.badssl.com"),
    # === badssl.com Test Suite - Invalid Certificates (expect_fail=True) ===
    # Certificate validation failures
    TestCase("badssl_expired", "expired.badssl.com", expect_fail=True),
    TestCase("badssl_wrong_host", "wrong.host.badssl.com", expect_fail=True),
    TestCase("badssl_self_signed", "self-signed.badssl.com", expect_fail=True),
    TestCase("badssl_untrusted_root", "untrusted-root.badssl.com", expect_fail=True),
    TestCase("badssl_incomplete_chain", "incomplete-chain.badssl.com", expect_fail=True),
    TestCase("badssl_no_common_name", "no-common-name.badssl.com", expect_fail=True),
    TestCase("badssl_no_subject", "no-subject.badssl.com", expect_fail=True),
    # Known compromised/malicious root CAs
    TestCase("badssl_superfish", "superfish.badssl.com", expect_fail=True),
    TestCase("badssl_edellroot", "edellroot.badssl.com", expect_fail=True),
    TestCase("badssl_dsdtestprovider", "dsdtestprovider.badssl.com", expect_fail=True),
    TestCase("badssl_webpack", "webpack-dev-server.badssl.com", expect_fail=True),
    # SHA-1 certificates (deprecated)
    TestCase("badssl_sha1_2016", "sha1-2016.badssl.com", expect_fail=True),
    TestCase("badssl_sha1_2017", "sha1-2017.badssl.com", expect_fail=True),
    TestCase("badssl_sha1_intermediate", "sha1-intermediate.badssl.com", expect_fail=True),
    # Note: revoked.badssl.com not included - requires OCSP/CRL checking (not implemented)
    # Note: pinning-test.badssl.com not relevant - we don't implement certificate pinning
    # Note: client.badssl.com/client-cert-missing.badssl.com - require client certs (different use case)
]


class IntegrationTests(unittest.TestCase):
    """Integration tests - dynamically generated from TEST_CASES"""

    @classmethod
    def setUpClass(cls):
        """Ensure cacert.pem is downloaded before running tests"""
        subprocess.run([sys.executable, str(CRYPTO_CLI), "get-cacert"], capture_output=True, check=False)

    def run_crypto(self, host: str, expect_fail: bool = False, max_depth: int = None) -> subprocess.CompletedProcess:
        """Run crypto CLI and return the result"""
        cmd = [sys.executable, str(CRYPTO_CLI), "host-check", host]
        if expect_fail:
            cmd.append("--expect-fail")
        if max_depth is not None:
            cmd.extend(["--max-depth", str(max_depth)])

        return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


# Dynamically generate test methods from TEST_CASES (one-liner per test!)
for tc in TEST_CASES:
    setattr(
        IntegrationTests,
        f"test_{tc.name}",
        lambda self, t=tc: self.assertEqual(
            self.run_crypto(t.host, t.expect_fail, t.max_depth).returncode,
            0,
            f"Test {t.name} failed for {t.host}",
        ),
    )


if __name__ == "__main__":
    unittest.main()
