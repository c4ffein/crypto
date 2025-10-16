#!/usr/bin/env python3
"""
Integration test runner with TAP and JUnit XML output support
"""

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from xml.etree import ElementTree as ET


@dataclass
class TestCase:
    name: str
    host: str
    expect_fail: bool = False


@dataclass
class TestResult:
    test_case: TestCase
    passed: bool
    duration: float
    output: str
    error: Optional[str] = None


# Test cases
TEST_CASES = [
    # Google Services (non-standard ports)
    TestCase("gmail_smtp", "smtp.gmail.com:465"),
    TestCase("gmail_imap", "imap.gmail.com:993"),
    # Services you use (dogfooding)
    TestCase("anthropic_api", "api.anthropic.com"),
    TestCase("qonto_thirdparty", "thirdparty.qonto.com"),
    # Note: AWS S3 has a very deep cert chain (>4), exceeds default max-depth
    TestCase("qonto_s3", "qonto.s3.eu-central-1.amazonaws.com"),
    # Popular services (CA diversity)
    TestCase("github", "github.com"),
    TestCase("cloudflare", "cloudflare.com"),
    TestCase("letsencrypt", "letsencrypt.org"),
    TestCase("eff", "www.eff.org"),
    TestCase("badssl", "badssl.com"),
    # === badssl.com Test Suite - Valid Certificates ===
    # Modern signature algorithms
    TestCase("badssl_sha256", "sha256.badssl.com"),
    # Note: sha384/sha512 fail at TLS handshake level (Python's SSL rejects them)
    # ECC certificates (should pass)
    TestCase("badssl_ecc256", "ecc256.badssl.com"),
    TestCase("badssl_ecc384", "ecc384.badssl.com"),
    # RSA key sizes (should pass)
    TestCase("badssl_rsa2048", "rsa2048.badssl.com"),
    TestCase("badssl_rsa4096", "rsa4096.badssl.com"),
    # Note: extended-validation and 1000-sans fail at TLS handshake (cert size/complexity issues)
    # === badssl.com Test Suite - Invalid Certificates (expect_fail=True) ===
    # Certificate validation failures
    TestCase("badssl_expired", "expired.badssl.com", expect_fail=True),
    TestCase("badssl_wrong_host", "wrong.host.badssl.com", expect_fail=True),
    TestCase("badssl_self_signed", "self-signed.badssl.com", expect_fail=True),
    TestCase("badssl_untrusted_root", "untrusted-root.badssl.com", expect_fail=True),
    # Note: revoked cert detection requires OCSP/CRL checking (not implemented)
    # revoked.badssl.com passes because we don't check revocation status
    TestCase("badssl_no_common_name", "no-common-name.badssl.com", expect_fail=True),
    TestCase("badssl_no_subject", "no-subject.badssl.com", expect_fail=True),
    TestCase("badssl_incomplete_chain", "incomplete-chain.badssl.com", expect_fail=True),
]


def run_test(crypto_cli: Path, test_case: TestCase, verbose: bool = False) -> TestResult:
    """Run a single test case"""
    cmd = [str(crypto_cli), "host-check", test_case.host]

    if test_case.expect_fail:
        cmd.append("--expect-fail")

    if verbose:
        cmd.insert(1, "-v")

    start_time = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        duration = time.time() - start_time

        passed = result.returncode == 0
        output = result.stdout + result.stderr

        return TestResult(
            test_case=test_case,
            passed=passed,
            duration=duration,
            output=output,
            error=None if passed else f"Exit code: {result.returncode}",
        )
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        return TestResult(
            test_case=test_case,
            passed=False,
            duration=duration,
            output="",
            error="Test timed out after 30 seconds",
        )
    except Exception as e:
        duration = time.time() - start_time
        return TestResult(
            test_case=test_case,
            passed=False,
            duration=duration,
            output="",
            error=str(e),
        )


def output_tap(results: List[TestResult]):
    """Output results in TAP (Test Anything Protocol) format"""
    print(f"1..{len(results)}")

    for i, result in enumerate(results, 1):
        status = "ok" if result.passed else "not ok"
        print(f"{status} {i} - {result.test_case.name} ({result.test_case.host})")

        if not result.passed and result.error:
            for line in result.error.split("\n"):
                print(f"  # {line}")


def output_junit(results: List[TestResult], output_file: Path):
    """Output results in JUnit XML format"""
    total = len(results)
    failures = sum(1 for r in results if not r.passed)
    total_time = sum(r.duration for r in results)

    testsuite = ET.Element(
        "testsuite",
        name="crypto-integration-tests",
        tests=str(total),
        failures=str(failures),
        time=f"{total_time:.3f}",
    )

    for result in results:
        testcase = ET.SubElement(
            testsuite,
            "testcase",
            name=result.test_case.name,
            classname=f"integration.{result.test_case.name}",
            time=f"{result.duration:.3f}",
        )

        if not result.passed:
            failure = ET.SubElement(
                testcase,
                "failure",
                message=result.error or "Test failed",
            )
            failure.text = result.output

        # Add system-out for all tests
        system_out = ET.SubElement(testcase, "system-out")
        system_out.text = result.output

    tree = ET.ElementTree(testsuite)
    ET.indent(tree, space="  ")
    tree.write(output_file, encoding="utf-8", xml_declaration=True)


def output_human(results: List[TestResult]):
    """Output results in human-readable format"""
    print("=== Integration Test Results ===\n")

    passed = 0
    failed = 0

    for result in results:
        status = "✓ PASS" if result.passed else "✗ FAIL"
        color = "\033[0;32m" if result.passed else "\033[0;31m"
        reset = "\033[0m"

        print(f"{color}{status}{reset} {result.test_case.name} - {result.test_case.host} ({result.duration:.2f}s)")

        if not result.passed and result.error:
            print(f"      Error: {result.error}")

        if result.passed:
            passed += 1
        else:
            failed += 1

    print(f"\n{'=' * 40}")
    print(f"Total:  {len(results)}")
    print(f"\033[0;32mPassed: {passed}\033[0m")
    if failed > 0:
        print(f"\033[0;31mFailed: {failed}\033[0m")
    else:
        print(f"Failed: {failed}")
    print(f"{'=' * 40}")


def main():
    parser = argparse.ArgumentParser(description="Run crypto integration tests")
    parser.add_argument(
        "--format",
        choices=["human", "tap", "junit"],
        default="human",
        help="Output format (default: human)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for JUnit XML (only used with --format=junit)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output from crypto tool",
    )
    parser.add_argument(
        "--crypto-cli",
        type=Path,
        default=Path(__file__).parent.parent / "crypto.py",
        help="Path to crypto.py CLI tool",
    )

    args = parser.parse_args()

    # Ensure cacert.pem exists
    subprocess.run(
        [str(args.crypto_cli), "get-cacert"],
        capture_output=True,
    )

    # Run all tests
    results = []
    for test_case in TEST_CASES:
        result = run_test(args.crypto_cli, test_case, verbose=args.verbose)
        results.append(result)

    # Output results in requested format
    if args.format == "tap":
        output_tap(results)
    elif args.format == "junit":
        output_file = args.output or Path("test-results.xml")
        output_junit(results, output_file)
        print(f"Results written to {output_file}")
    else:
        output_human(results)

    # Exit with appropriate code
    failed = sum(1 for r in results if not r.passed)
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
