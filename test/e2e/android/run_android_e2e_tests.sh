#!/usr/bin/env bash
# File: test/e2e/android/run_android_e2e_tests.sh
# Master test runner for Android E2E tests.
# Runs all Android E2E test suites and reports overall results.
# Intended to be called from CI where the script runner executes each line separately.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Track overall test failures
TEST_FAILURES=0

echo "=== Running TLS E2E Test ==="
if bash "$SCRIPT_DIR/android_tls_e2e_test.sh"; then
    echo "✅ TLS test PASSED"
else
    echo "❌ TLS test FAILED"
    TEST_FAILURES=$((TEST_FAILURES + 1))
fi

echo "=== Running Bash E2E Test ==="
if bash "$SCRIPT_DIR/android_bash_e2e_test.sh"; then
    echo "✅ Bash test PASSED"
else
    echo "❌ Bash test FAILED"
    TEST_FAILURES=$((TEST_FAILURES + 1))
fi

echo "=== Running GoTLS E2E Test ==="
if bash "$SCRIPT_DIR/android_gotls_e2e_test.sh"; then
    echo "✅ GoTLS test PASSED"
else
    echo "❌ GoTLS test FAILED"
    TEST_FAILURES=$((TEST_FAILURES + 1))
fi

echo "=== Test execution completed ==="
if [ "$TEST_FAILURES" -gt 0 ]; then
    echo "❌ $TEST_FAILURES test suite(s) FAILED"
    exit 1
fi
echo "✅ All test suites PASSED"
