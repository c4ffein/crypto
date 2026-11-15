#!/usr/bin/env python3
"""
Tests for exit codes following Unix conventions
"""

import subprocess
import unittest
from pathlib import Path


class TestExitCodes(unittest.TestCase):
    """Test that exit codes follow conventions"""

    @staticmethod
    def get_crypto_path():
        return Path(__file__).parent.parent / "crypto.py"

    def test_help_exits_zero(self):
        """--help should exit with code 0"""
        result = subprocess.run(
            ["python3", str(self.get_crypto_path()), "--help"],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, "Help should exit with code 0")

    def test_no_args_exits_zero(self):
        """No arguments (shows help) should exit with code 0"""
        result = subprocess.run(
            ["python3", str(self.get_crypto_path())],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, "No args (help) should exit with code 0")

    def test_invalid_command_exits_nonzero(self):
        """Invalid command should exit with non-zero code"""
        result = subprocess.run(
            ["python3", str(self.get_crypto_path()), "invalid-command"],
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0, "Invalid command should exit non-zero")

    def run_host_check(self, *args):
        return subprocess.run(
            ["python3", str(self.get_crypto_path()), "host-check", *args],
            capture_output=True,
            text=True,
        )

    def test_unresolvable_host_exits_one_without_traceback(self):
        """A DNS failure is a clean error, not a raw traceback (.invalid never resolves, RFC 2606)"""
        result = self.run_host_check("nonexistent.invalid")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertIn("Unable to resolve host", result.stdout + result.stderr)

    def test_out_of_range_port_exits_one_without_traceback(self):
        """A port outside 1-65535 is rejected while parsing, before any connection"""
        result = self.run_host_check("example.com:99999")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertIn("Unable to parse host", result.stdout + result.stderr)

    def test_network_error_is_not_an_expected_failure(self):
        """--expect-fail expects a verification failure: an unreachable host proves nothing and must still fail"""
        result = self.run_host_check("nonexistent.invalid", "--expect-fail")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
