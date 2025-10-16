#!/bin/bash
# Integration tests for crypto CLI tool
# Tests against real-world TLS endpoints

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRYPTO_CLI="$SCRIPT_DIR/../crypto.py"

# Test counters
TOTAL=0
PASSED=0
FAILED=0

echo "=== Integration Tests for crypto CLI ==="
echo

# Ensure cacert.pem exists
echo "→ Ensuring cacert.pem exists..."
if ! "$CRYPTO_CLI" get-cacert >/dev/null 2>&1; then
    echo "  (already exists)"
fi
echo

test_host() {
    local host="$1"
    local expect_fail="${2:-false}"

    TOTAL=$((TOTAL + 1))

    if [ "$expect_fail" = "true" ]; then
        echo -e "${YELLOW}→ Testing (expect failure): $host${NC}"
    else
        echo "→ Testing: $host"
    fi

    if output=$("$CRYPTO_CLI" host-check "$host" 2>&1); then
        if [ "$expect_fail" = "true" ]; then
            echo -e "${RED}  ✗ FAIL - Expected failure but succeeded${NC}"
            echo "  Output: $output"
            FAILED=$((FAILED + 1))
            return 1
        else
            echo -e "${GREEN}  ✓ PASS${NC}"
            PASSED=$((PASSED + 1))
        fi
    else
        if [ "$expect_fail" = "true" ]; then
            echo -e "${GREEN}  ✓ PASS (failed as expected)${NC}"
            PASSED=$((PASSED + 1))
        else
            echo -e "${RED}  ✗ FAIL${NC}"
            echo "  Output: $output"
            FAILED=$((FAILED + 1))
            return 1
        fi
    fi
    echo
}

echo "=== Google Services (non-standard ports) ==="
test_host "smtp.gmail.com:465"
test_host "imap.gmail.com:993"

echo "=== Services You Use (dogfooding) ==="
test_host "api.anthropic.com"
test_host "thirdparty.qonto.com"
test_host "qonto.s3.eu-central-1.amazonaws.com"

echo "=== Popular Services (CA diversity) ==="
test_host "github.com"
test_host "cloudflare.com"
test_host "letsencrypt.org"

echo "=== Additional Coverage ==="
test_host "www.eff.org"
test_host "badssl.com"

echo "=== Negative Test Cases ==="
test_host "expired.badssl.com" true
test_host "wrong.host.badssl.com" true
test_host "self-signed.badssl.com" true

echo "=========================================="
echo -e "Total:  $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
else
    echo -e "Failed: $FAILED"
fi
echo "=========================================="

if [ $FAILED -gt 0 ]; then
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
