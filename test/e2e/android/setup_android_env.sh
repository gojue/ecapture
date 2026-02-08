#!/usr/bin/env bash
# File: test/e2e/android/setup_android_env.sh
# Setup and verify Android environment for e2e tests
# Requirements: ADB, Android device/emulator with root

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/android/common_android.sh
source "$SCRIPT_DIR/common_android.sh"

# Main setup function
main() {
    log_info "=== Android E2E Test Environment Setup ==="

    # Step 1: Check ADB
    log_info "=== Step 1: Check ADB ==="
    if ! check_adb; then
        log_error "ADB check failed"
        exit 1
    fi

    # Step 2: Check device connection
    log_info "=== Step 2: Check Android Device ==="
    if ! check_android_device; then
        log_error "No Android device found"
        log_info ""
        log_info "Please connect an Android device or start an emulator:"
        log_info "  - Physical device: Enable USB debugging and connect via USB"
        log_info "  - Emulator: Use Android Studio or command line tools"
        log_info ""
        log_info "Example emulator commands:"
        log_info "  emulator -avd <avd_name> -writable-system"
        log_info ""
        exit 1
    fi

    wait_for_device

    # Step 3: Display device info
    log_info "=== Step 3: Device Information ==="

    local device_model
    device_model=$(get_device_prop "ro.product.model")
    log_info "Device model: $device_model"

    local device_brand
    device_brand=$(get_device_prop "ro.product.brand")
    log_info "Device brand: $device_brand"

    local sdk_version
    sdk_version=$(get_device_prop "ro.build.version.sdk")
    log_info "Android SDK: $sdk_version"

    local release
    release=$(get_device_prop "ro.build.version.release")
    log_info "Android version: $release"

    # Step 4: Check Android version
    log_info "=== Step 4: Check Android Version ==="
    if ! check_android_version; then
        log_error "Android version check failed"
        log_info "Required: Android 15+ (SDK 35+)"
        log_warn "Tests may fail on older Android versions"
    fi

    # Step 5: Check kernel
    log_info "=== Step 5: Check Kernel Version ==="
    if ! check_android_kernel; then
        log_error "Kernel version check failed"
        log_warn "Required: Kernel 5.5+ for ARM64"
        log_warn "Tests may fail with older kernels"
    fi

    # Step 6: Check architecture
    log_info "=== Step 6: Check Architecture ==="
    if ! check_android_arch; then
        log_error "Architecture check failed"
        log_info "Required: ARM64/aarch64"
        exit 1
    fi

    # Step 7: Check root access
    log_info "=== Step 7: Check Root Access ==="
    if ! check_android_root; then
        log_error "Root access check failed"
        log_info ""
        log_info "Tests require root access. Options:"
        log_info "  1. Use rooted physical device"
        log_info "  2. Use Android emulator (easier to get root)"
        log_info ""
        log_info "For emulator, run 'adb root' to enable root"
        log_info ""
        exit 1
    fi

    # Step 8: Check SELinux
    log_info "=== Step 8: Check SELinux ==="
    if ! check_selinux; then
        log_warn "SELinux is in Enforcing mode"

        # Try to set permissive
        if set_selinux_permissive; then
            log_success "SELinux set to permissive mode"
        else
            log_error "Could not set SELinux to permissive"
            log_info "eBPF operations may be blocked by SELinux"
            log_info "Consider using 'adb shell setenforce 0' manually"
        fi
    else
        log_success "SELinux is permissive or disabled"
    fi

    # Step 9: Check available tools
    log_info "=== Step 9: Check Available Tools on Device ==="

    local tools_available=0
    local tools_missing=0

    # Check curl
    if adb_command_exists "curl"; then
        log_success "curl: available"
        tools_available=$((tools_available + 1))
    else
        log_warn "curl: not available"
        tools_missing=$((tools_missing + 1))
    fi

    # Check wget
    if adb_command_exists "wget"; then
        log_success "wget: available"
        tools_available=$((tools_available + 1))
    else
        log_warn "wget: not available"
        tools_missing=$((tools_missing + 1))
    fi

    # Check sh
    if adb_command_exists "sh"; then
        log_success "sh: available"
        tools_available=$((tools_available + 1))
    else
        log_error "sh: not available (critical)"
        exit 1
    fi

    if [ $tools_missing -gt 0 ]; then
        log_warn "Some tools are missing. TLS tests may not work without curl/wget."
        log_info "Consider using a device with busybox or similar tools installed."
    fi

    # Step 10: Check binaries
    log_info "=== Step 10: Check Test Binaries ==="

    local ecapture_bin="$ROOT_DIR/bin/ecapture"
    if [ -f "$ecapture_bin" ]; then
        log_success "ecapture binary found: $ecapture_bin"

        # Verify it's ARM64
        if file "$ecapture_bin" | grep -q "ARM aarch64"; then
            log_success "Binary architecture: ARM64 (correct)"
        else
            log_error "Binary is not ARM64"
            log_info "Rebuild with: ANDROID=1 make nocore"
            exit 1
        fi
    else
        log_error "ecapture binary not found"
        log_info "Build it first:"
        log_info "  cd $ROOT_DIR"
        log_info "  ANDROID=1 make nocore"
        exit 1
    fi

    local go_client="$SCRIPT_DIR/go_https_client_android"
    if [ -f "$go_client" ]; then
        log_success "Go HTTPS client found: $go_client"
    else
        log_warn "Go HTTPS client not found (optional)"
        log_info "Build it with: $SCRIPT_DIR/build_android_tests.sh"
    fi

    # Step 11: Summary
    log_info "=== Setup Summary ==="
    log_success "✓ ADB available"
    log_success "✓ Android device connected"
    log_success "✓ Root access granted"
    log_success "✓ Required binaries present"

    log_info ""
    log_info "=== Environment Ready ==="
    log_info ""
    log_info "You can now run Android e2e tests:"
    log_info ""
    log_info "Individual tests:"
    log_info "  bash $SCRIPT_DIR/android_tls_e2e_test.sh"
    log_info "  bash $SCRIPT_DIR/android_gotls_e2e_test.sh"
    log_info "  bash $SCRIPT_DIR/android_bash_e2e_test.sh"
    log_info ""
    log_info "Or use Makefile (from project root):"
    log_info "  make e2e-android-tls"
    log_info "  make e2e-android-gotls"
    log_info "  make e2e-android-bash"
    log_info "  make e2e-android-all"
    log_info ""

    exit 0
}

main
