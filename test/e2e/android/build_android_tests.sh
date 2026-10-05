#!/usr/bin/env bash
# Build eCapture and the Android Conscrypt/BoringSSL E2E workload on Linux.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
API_LEVEL="${ANDROID_API_LEVEL:-33}"
TARGET_ARCH="${CROSS_ARCH:-arm64}"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Android artifacts must be built on Linux" >&2
    exit 1
fi
IFS=. read -r host_kernel_major host_kernel_minor _ <<<"$(uname -r)"
if ((host_kernel_major < 4 || (host_kernel_major == 4 && host_kernel_minor < 18))); then
    echo "Linux kernel 4.18+ is required" >&2
    exit 1
fi
if ! command -v go >/dev/null 2>&1 || ! command -v clang >/dev/null 2>&1; then
    echo "Go and clang are required" >&2
    exit 1
fi

cd "$ROOT_DIR"
CROSS_ARCH="$TARGET_ARCH" ANDROID=1 make nocore -j "$(nproc)"
bash "$SCRIPT_DIR/build_boringssl_client.sh" "$API_LEVEL"

test -x "$ROOT_DIR/bin/ecapture"
test -s "$SCRIPT_DIR/android_boringssl_client.jar"
echo "Built Android eCapture ($TARGET_ARCH) and BoringSSL E2E workload for API $API_LEVEL"
