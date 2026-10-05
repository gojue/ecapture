#!/usr/bin/env bash
# Validate the Android 13+ BoringSSL E2E environment without running captures.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/android/common_android.sh
source "$SCRIPT_DIR/common_android.sh"

check_android_prerequisites

[[ -f "$ROOT_DIR/bin/ecapture" ]] || {
    log_error "Android eCapture binary is missing: $ROOT_DIR/bin/ecapture"
    exit 1
}
[[ -f "$SCRIPT_DIR/android_boringssl_client.jar" ]] || {
    log_error "BoringSSL workload is missing: $SCRIPT_DIR/android_boringssl_client.jar"
    log_info "Run: $SCRIPT_DIR/build_boringssl_client.sh"
    exit 1
}

boringssl_path="$(find_android_boringssl)"
log_success "Android E2E environment is ready (BoringSSL: $boringssl_path)"
