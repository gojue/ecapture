#!/usr/bin/env bash
# Compatibility entry point. The maintained Linux suite lives under linux/.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/linux/gnutls_test.sh" "$@"
