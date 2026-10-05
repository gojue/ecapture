#!/usr/bin/env bash
# Validate the Android 13+ BoringSSL E2E environment without running captures.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/android/common_android.sh
source "$SCRIPT_DIR/common_android.sh"

check_android_prerequisites

local_ecapture="${ECAPTURE_BINARY:-$ROOT_DIR/bin/ecapture}"
local_client="${ANDROID_BORINGSSL_CLIENT:-$SCRIPT_DIR/android_boringssl_client.jar}"
device_ecapture="/data/local/tmp/ecapture-e2e-setup-$$"

cleanup_setup_binary() {
    adb_cmd shell "rm -f '$device_ecapture'" >/dev/null 2>&1 || true
}
trap cleanup_setup_binary EXIT

[[ -f "$local_ecapture" ]] || {
    log_error "Android eCapture binary is missing: $local_ecapture"
    exit 1
}
[[ -f "$local_client" ]] || {
    log_error "BoringSSL workload is missing: $local_client"
    log_info "Run: $SCRIPT_DIR/build_boringssl_client.sh"
    exit 1
}

adb_push "$local_ecapture" "$device_ecapture"
adb_cmd shell "chmod 755 '$device_ecapture'"
if ! ecapture_version="$(adb_cmd shell "'$device_ecapture' --version" 2>&1)"; then
    log_error "Android eCapture binary cannot execute on the connected device: $local_ecapture"
    printf '%s\n' "$ecapture_version" >&2
    exit 1
fi

boringssl_path="$(find_android_boringssl)"
ecapture_version="$(printf '%s' "$ecapture_version" | tr -d '\r\n')"
log_success "Android E2E environment is ready (eCapture: $ecapture_version; BoringSSL: $boringssl_path)"
