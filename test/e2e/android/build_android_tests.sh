#!/usr/bin/env bash
# File: test/e2e/android/build_android_tests.sh
# Build ecapture and test binaries for Android
# Requirements: Linux environment with Android NDK

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# Check if running on Linux
check_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "This script must run on Linux"
        log_info "Current OS: $(uname -s)"
        log_info "For macOS, build on remote Linux server:"
        log_info "  ssh cfc4n@172.16.71.128 'cd /home/cfc4n/project/ecapture && ./test/e2e/android/build_android_tests.sh'"
        return 1
    fi
    return 0
}

# Check kernel version
check_kernel() {
    local kernel_version
    kernel_version=$(uname -r | cut -d'.' -f1,2)
    local major minor
    major=$(echo "$kernel_version" | cut -d'.' -f1)
    minor=$(echo "$kernel_version" | cut -d'.' -f2)

    if [ "$major" -lt 4 ] || { [ "$major" -eq 4 ] && [ "$minor" -lt 18 ]; }; then
        log_error "Kernel version $kernel_version is too old. Required: >= 4.18"
        return 1
    fi

    log_info "Kernel version: $kernel_version - OK"
    return 0
}

# Check Go version
check_go() {
    if ! command -v go >/dev/null 2>&1; then
        log_error "Go not found. Please install Go 1.21+"
        return 1
    fi

    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $go_version"
    return 0
}

# Check clang
check_clang() {
    if ! command -v clang >/dev/null 2>&1; then
        log_error "Clang not found. Please install clang/llvm"
        return 1
    fi

    local clang_version
    clang_version=$(clang --version | head -1)
    log_info "Clang: $clang_version"
    return 0
}

# Build ecapture for Android
build_ecapture() {
    log_info "=== Building eCapture for Android ==="

    cd "$ROOT_DIR"

    log_info "Cleaning previous builds..."
    make clean >/dev/null 2>&1 || true

    log_info "Building with ANDROID=1 make nocore..."
    if ANDROID=1 make nocore -j "$(nproc)"; then
        log_success "eCapture built successfully"

        if [ -f "$ROOT_DIR/bin/ecapture" ]; then
            local size
            size=$(stat -c%s "$ROOT_DIR/bin/ecapture")
            log_info "Binary size: $((size / 1024 / 1024)) MB"
            log_info "Binary location: $ROOT_DIR/bin/ecapture"

            # Check architecture
            local arch
            arch=$(file "$ROOT_DIR/bin/ecapture" | grep -o "ARM aarch64" || echo "unknown")
            log_info "Architecture: $arch"

            return 0
        else
            log_error "Binary not found after build"
            return 1
        fi
    else
        log_error "Build failed"
        return 1
    fi
}

# Build Go HTTPS client for Android
build_go_client() {
    log_info "=== Building Go HTTPS Client for Android ==="

    local go_source="$ROOT_DIR/test/e2e/go_https_client.go"
    local go_output="$SCRIPT_DIR/go_https_client_android"

    if [ ! -f "$go_source" ]; then
        log_error "Go client source not found: $go_source"
        return 1
    fi

    cd "$ROOT_DIR/test/e2e"

    log_info "Compiling for Android ARM64..."
    if CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o "$go_output" go_https_client.go; then
        log_success "Go client built successfully"
        log_info "Output: $go_output"

        local size
        size=$(stat -c%s "$go_output")
        log_info "Binary size: $((size / 1024)) KB"

        return 0
    else
        log_error "Failed to build Go client"
        return 1
    fi
}

# Main
main() {
    log_info "=== Android Test Build Script ==="

    # Prerequisites check
    log_info "=== Checking Prerequisites ==="

    if ! check_linux; then
        exit 1
    fi

    if ! check_kernel; then
        exit 1
    fi

    if ! check_go; then
        exit 1
    fi

    if ! check_clang; then
        exit 1
    fi

    log_success "All prerequisites met"

    # Build ecapture
    if ! build_ecapture; then
        log_error "Failed to build ecapture"
        exit 1
    fi

    # Build Go client
    if ! build_go_client; then
        log_warn "Failed to build Go client (tests will use curl instead)"
    fi

    log_success "=== Build Complete ==="
    log_info ""
    log_info "Built binaries:"
    log_info "  - $ROOT_DIR/bin/ecapture"
    log_info "  - $SCRIPT_DIR/go_https_client_android"
    log_info ""
    log_info "To run tests:"
    log_info "  1. Connect Android device via ADB"
    log_info "  2. Run: bash $SCRIPT_DIR/setup_android_env.sh"
    log_info "  3. Run individual tests:"
    log_info "     bash $SCRIPT_DIR/android_tls_e2e_test.sh"
    log_info "     bash $SCRIPT_DIR/android_gotls_e2e_test.sh"
    log_info "     bash $SCRIPT_DIR/android_bash_e2e_test.sh"
    log_info ""
    log_info "Or use Makefile targets:"
    log_info "  make e2e-android-tls"
    log_info "  make e2e-android-gotls"
    log_info "  make e2e-android-bash"
    log_info "  make e2e-android-all"
}

main
