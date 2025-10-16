#!/usr/bin/env python3
"""
Integration tests as individual unittest test cases for easier debugging
"""

import subprocess
import unittest
from pathlib import Path


def get_crypto_path():
    return Path(__file__).parent.parent / "crypto.py"


def run_host_check(host: str, expect_fail: bool = False, max_depth: int = 6) -> subprocess.CompletedProcess:
    """Helper to run crypto host-check"""
    cmd = ["python3", str(get_crypto_path()), "host-check", host, "--max-depth", str(max_depth)]
    if expect_fail:
        cmd.append("--expect-fail")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


class TestIntegrationGoogleServices(unittest.TestCase):
    """Test Google services (non-standard ports)"""

    def test_gmail_smtp(self):
        result = run_host_check("smtp.gmail.com:465")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    def test_gmail_imap(self):
        result = run_host_check("imap.gmail.com:993")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")


class TestIntegrationServicesYouUse(unittest.TestCase):
    """Test services you use (dogfooding)"""

    def test_anthropic_api(self):
        result = run_host_check("api.anthropic.com")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    def test_qonto_thirdparty(self):
        result = run_host_check("thirdparty.qonto.com")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    def test_qonto_s3(self):
        # TODO FAILS: Amazon S3 serves an expired cross-signed cert in the chain (not our bug)
        result = run_host_check("qonto.s3.eu-central-1.amazonaws.com")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")


class TestIntegrationPopularServices(unittest.TestCase):
    """Test popular services (CA diversity)"""

    def test_github(self):
        result = run_host_check("github.com")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    def test_cloudflare(self):
        result = run_host_check("cloudflare.com")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    def test_letsencrypt(self):
        result = run_host_check("letsencrypt.org")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    def test_eff(self):
        result = run_host_check("www.eff.org")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    def test_badssl(self):
        result = run_host_check("badssl.com")
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")


class TestIntegrationNegativeCases(unittest.TestCase):
    """Test negative cases (should fail)"""

    def test_expired_cert(self):
        result = run_host_check("expired.badssl.com", expect_fail=True)
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    def test_wrong_host(self):
        result = run_host_check("wrong.host.badssl.com", expect_fail=True)
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")

    def test_self_signed(self):
        result = run_host_check("self-signed.badssl.com", expect_fail=True)
        self.assertEqual(result.returncode, 0, f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
