#!/usr/bin/env bash
# Build a dex/jar workload that uses Android Conscrypt/BoringSSL via app_process.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_LEVEL="${1:-${ANDROID_API_LEVEL:-33}}"
OUTPUT="${ANDROID_BORINGSSL_CLIENT:-$SCRIPT_DIR/android_boringssl_client.jar}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Android E2E workloads must be built on Linux" >&2
    exit 1
fi
IFS=. read -r host_kernel_major host_kernel_minor _ <<<"$(uname -r)"
if ((host_kernel_major < 4 || (host_kernel_major == 4 && host_kernel_minor < 18))); then
    echo "Linux kernel 4.18+ is required" >&2
    exit 1
fi
if [[ ! "$API_LEVEL" =~ ^[0-9]+$ ]] || ((API_LEVEL < 33)); then
    echo "Android 13/API 33 or newer is required" >&2
    exit 1
fi

if [[ -z "$ANDROID_SDK_ROOT" ]]; then
    echo "ANDROID_SDK_ROOT or ANDROID_HOME must be set" >&2
    exit 1
fi

ANDROID_JAR="$ANDROID_SDK_ROOT/platforms/android-$API_LEVEL/android.jar"
if [[ ! -f "$ANDROID_JAR" ]]; then
    echo "Android platform $API_LEVEL is not installed: $ANDROID_JAR" >&2
    exit 1
fi

BUILD_TOOLS_DIR="$(find "$ANDROID_SDK_ROOT/build-tools" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
D8="$BUILD_TOOLS_DIR/d8"
if [[ ! -x "$D8" ]]; then
    echo "d8 not found under $ANDROID_SDK_ROOT/build-tools" >&2
    exit 1
fi

BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ecapture-android-client.XXXXXX")"
trap 'rm -rf -- "$BUILD_DIR"' EXIT
mkdir -p "$BUILD_DIR/classes" "$BUILD_DIR/dex"

javac -source 8 -target 8 -Xlint:-options -classpath "$ANDROID_JAR" \
    -d "$BUILD_DIR/classes" "$SCRIPT_DIR/AndroidHttpsClient.java"
# All generated nested classes are inputs to d8.
"$D8" --min-api 33 --output "$BUILD_DIR/dex" "$BUILD_DIR/classes"/*.class
jar --create --file "$OUTPUT" -C "$BUILD_DIR/dex" classes.dex

echo "Built Android Conscrypt/BoringSSL client: $OUTPUT"
