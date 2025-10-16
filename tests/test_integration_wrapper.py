#!/usr/bin/env python3
"""
Wrapper to run integration tests via unittest
"""

import subprocess
import unittest
from pathlib import Path


class TestIntegration(unittest.TestCase):
    """Run integration tests as a single unittest"""

    def test_integration_suite(self):
        """Run all integration tests"""
        integration_script = Path(__file__).parent / "test_integration.py"
        result = subprocess.run(
            ["python3", str(integration_script)],
            capture_output=True,
            text=True,
        )

        # Print output for visibility
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)

        # Assert success
        self.assertEqual(
            result.returncode,
            0,
            f"Integration tests failed with exit code {result.returncode}",
        )


if __name__ == "__main__":
    unittest.main()
