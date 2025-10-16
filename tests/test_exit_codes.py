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


if __name__ == "__main__":
    unittest.main()
