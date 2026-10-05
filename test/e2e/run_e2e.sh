#!/usr/bin/env bash
# Run the maintained Linux TLS suites. Defaults to all three modules.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES="${E2E_MODULES:-tls gotls gnutls}"
failures=0

for module in $MODULES; do
    case "$module" in
        tls|gotls|gnutls) ;;
        *)
            printf '[FAIL] Unknown E2E module: %s\n' "$module" >&2
            failures=$((failures + 1))
            continue
            ;;
    esac

    printf '\n===== Linux %s E2E =====\n' "$module"
    if ! bash "$SCRIPT_DIR/linux/${module}_test.sh"; then
        failures=$((failures + 1))
    fi
done

if ((failures > 0)); then
    printf '\n[FAIL] %d Linux E2E suite(s) failed\n' "$failures" >&2
    exit 1
fi
printf '\n[PASS] All Linux E2E suites passed\n'
