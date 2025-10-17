#!/usr/bin/env python3
"""
Test runner for crypto CLI tool

Usage:
    python test.py              # Run ALL tests (unit + integration)
    python test.py --all        # Run ALL tests (unit + integration)
    python test.py --unit       # Run unit tests only
    python test.py --integration # Run integration tests only
"""

import sys
import unittest

if __name__ == "__main__":
    # Determine which tests to run - default is ALL
    run_all = "--all" in sys.argv or len(sys.argv) == 1
    run_unit_only = "--unit" in sys.argv
    run_integration_only = "--integration" in sys.argv

    # Remove custom args so unittest doesn't see them
    sys.argv = [arg for arg in sys.argv if not arg.startswith("--")]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    if run_all:
        # Discover ALL test_*.py files (includes integration tests)
        print("=" * 70)
        print("Running all tests...")
        print("=" * 70)
        suite.addTests(loader.discover("tests", pattern="test_*.py"))
    elif run_unit_only:
        # Discover unit tests only (exclude test_integration.py)
        print("=" * 70)
        print("Running unit tests...")
        print("=" * 70)
        for pattern in ["test_security.py", "test_help.py", "test_exit_codes.py"]:
            suite.addTests(loader.discover("tests", pattern=pattern))
    elif run_integration_only:
        # Discover integration tests only
        print("=" * 70)
        print("Running integration tests...")
        print("=" * 70)
        suite.addTests(loader.discover("tests", pattern="test_integration.py"))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    sys.exit(0 if result.wasSuccessful() else 1)
