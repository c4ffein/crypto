#!/usr/bin/env python3
"""
Tests for help output and CLI interface
"""

import subprocess
import unittest
from pathlib import Path


class TestHelpSync(unittest.TestCase):
    """Test that README.md and --help output stay in sync"""

    @staticmethod
    def get_crypto_path():
        return Path(__file__).parent.parent / "crypto.py"

    def get_help_from_cli(self):
        """Get help output from the CLI"""
        result = subprocess.run(
            ["python3", str(self.get_crypto_path()), "--help"],
            capture_output=True,
            text=True,
        )
        output = result.stdout or result.stderr
        return output.strip()

    def get_help_from_readme(self):
        """Extract help section from README.md"""
        readme_path = Path(__file__).parent.parent / "README.md"
        readme = readme_path.read_text()

        start_marker = "## Usage\n\n```\n"
        end_marker = "\n```\n\n## Examples"

        start = readme.find(start_marker)
        end = readme.find(end_marker)

        if start == -1 or end == -1:
            self.fail("Could not find Usage section in README.md")

        help_text = readme[start + len(start_marker) : end]
        return help_text.strip()

    def test_help_matches_readme(self):
        """Verify that --help output matches README.md Usage section"""
        cli_help = self.get_help_from_cli()
        readme_help = self.get_help_from_readme()

        # Strip ANSI color codes from CLI output
        color_codes = ["\033[31m", "\033[32m", "\033[34m", "\033[90m", "\033[39m"]
        cli_help_no_color = cli_help
        for code in color_codes:
            cli_help_no_color = cli_help_no_color.replace(code, "")

        self.assertEqual(
            cli_help_no_color,
            readme_help,
            f"README.md and --help output are out of sync!\nCLI help:\n{cli_help_no_color}\n\nREADME help:\n{readme_help}",
        )


class TestHelpOutput(unittest.TestCase):
    """Test help output properties"""

    @staticmethod
    def get_crypto_path():
        return Path(__file__).parent.parent / "crypto.py"

    def test_help_goes_to_stdout(self):
        """Help should be printed to stdout, not stderr"""
        result = subprocess.run(
            ["python3", str(self.get_crypto_path()), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertIn("crypto - crypto tools", result.stdout)
        self.assertEqual(result.stderr, "", "Help should not print to stderr")

    def test_help_contains_all_commands(self):
        """Help should document all available commands"""
        result = subprocess.run(
            ["python3", str(self.get_crypto_path()), "--help"],
            capture_output=True,
            text=True,
        )
        help_text = result.stdout

        # Check for main commands
        self.assertIn("host-check", help_text)
        self.assertIn("get-cacert", help_text)

        # Check for options
        self.assertIn("--verbose", help_text)
        self.assertIn("--help", help_text)


if __name__ == "__main__":
    unittest.main()
