#!/usr/bin/env bash
# The maintained Android scope is the platform Conscrypt/BoringSSL TLS probe.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/android_tls_e2e_test.sh" "$@"
