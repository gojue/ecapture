#!/usr/bin/env bash
# File: test/e2e/android/common_android.sh
# Common utilities for ecapture Android e2e tests
# Requirements: Android 15+, ARM64, Kernel 5.5+

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check if running on macOS (development environment)
is_macos() {
    [[ "$(uname -s)" == "Darwin" ]]
}

# Check if ADB is available
check_adb() {
    if ! command -v adb >/dev/null 2>&1; then
        log_error "ADB not found. Please install Android SDK Platform Tools."
        log_info "Install: brew install --cask android-platform-tools (macOS)"
        return 1
    fi

    log_info "ADB version: $(adb --version | head -1)"
    return 0
}

# Check if Android device/emulator is connected
check_android_device() {
    if ! adb devices | grep -q "device$"; then
        log_error "No Android device connected. Please connect device or start emulator."
        log_info "Available devices:"
        adb devices
        return 1
    fi

    local device_count
    device_count=$(adb devices | grep "device$" | wc -l)
    log_info "Found $device_count Android device(s) connected"
    return 0
}

# Check Android version (require Android 15+, API 35+)
check_android_version() {
    local sdk_version
    sdk_version=$(adb shell getprop ro.build.version.sdk | tr -d '\r')

    if [ -z "$sdk_version" ]; then
        log_error "Failed to get Android SDK version"
        return 1
    fi

    log_info "Android SDK version: $sdk_version"

    if [ "$sdk_version" -lt 35 ]; then
        log_error "Android SDK version $sdk_version is too old. Required: >= 35 (Android 15)"
        return 1
    fi

    local release
    release=$(adb shell getprop ro.build.version.release | tr -d '\r')
    log_success "Android version: $release (SDK $sdk_version) - OK"
    return 0
}

# Check kernel version (require 5.5+ for ARM64)
check_android_kernel() {
    local kernel_version
    kernel_version=$(adb shell uname -r | tr -d '\r')

    log_info "Kernel version: $kernel_version"

    local major minor
    major=$(echo "$kernel_version" | cut -d'.' -f1)
    minor=$(echo "$kernel_version" | cut -d'.' -f2)

    if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 5 ]; }; then
        log_error "Kernel version $kernel_version is too old. Required: >= 5.5 for ARM64"
        return 1
    fi

    log_success "Kernel version: $kernel_version - OK"
    return 0
}

# Check CPU architecture (require ARM64)
check_android_arch() {
    local arch
    arch=$(adb shell uname -m | tr -d '\r')

    log_info "Architecture: $arch"

#    if [[ "$arch" != "aarch64" && "$arch" != "arm64" ]]; then
#        log_error "Architecture $arch is not supported. Required: aarch64/arm64"
#        return 1
#    fi

    log_success "Architecture: $arch - OK"
    return 0
}

# Check if device is rooted
check_android_root() {
    log_info "Checking root access..."

    if ! adb root >/dev/null 2>&1; then
        log_error "Failed to get root access. Tests require rooted device/emulator."
        return 1
    fi

    sleep 2
    adb wait-for-device

    # Verify root by checking uid
    local uid
    uid=$(adb shell id -u | tr -d '\r')

    if [ "$uid" != "0" ]; then
        log_error "Not running as root (uid=$uid). Tests require root."
        return 1
    fi

    log_success "Root access: OK (uid=$uid)"
    return 0
}

# Check SELinux status
check_selinux() {
    local selinux_status
    selinux_status=$(adb shell getenforce 2>/dev/null | tr -d '\r' || echo "Unknown")

    log_info "SELinux status: $selinux_status"

    if [ "$selinux_status" = "Enforcing" ]; then
        log_warn "SELinux is in Enforcing mode. eBPF may be restricted."
        log_info "To run tests, you may need to set SELinux to permissive:"
        log_info "  adb shell setenforce 0"
        return 1
    fi

    return 0
}

# Set SELinux to permissive mode
set_selinux_permissive() {
    log_info "Setting SELinux to permissive mode..."

    if adb shell setenforce 0 2>/dev/null; then
        log_success "SELinux set to permissive mode"
        return 0
    else
        log_error "Failed to set SELinux to permissive mode"
        return 1
    fi
}

# Push file to Android device
adb_push() {
    local src="$1"
    local dst="$2"

    if [ ! -f "$src" ]; then
        log_error "Source file not found: $src"
        return 1
    fi

    log_info "Pushing $src to $dst..."

    if adb push "$src" "$dst" >/dev/null 2>&1; then
        adb shell chmod 755 "$dst" 2>/dev/null || true
        log_success "Pushed: $src -> $dst"
        return 0
    else
        log_error "Failed to push file"
        return 1
    fi
}

# Pull file from Android device
adb_pull() {
    local src="$1"
    local dst="$2"

    log_info "Pulling $src from device..."

    if adb pull "$src" "$dst" >/dev/null 2>&1; then
        log_success "Pulled: $src -> $dst"
        return 0
    else
        log_error "Failed to pull file"
        return 1
    fi
}

# Execute command on Android device
adb_exec() {
    local cmd="$*"
    log_info "Executing on device: $cmd"
    adb shell "$cmd"
}

# Execute command on Android device as background process
adb_exec_bg() {
    local cmd="$*"
    log_info "Executing on device (background): $cmd"
    adb shell "$cmd &" &
}

# Kill process by name on Android device
adb_kill_by_name() {
    local process_name="$1"

    log_info "Killing processes matching '$process_name' on device..."

    local pids
    pids=$(adb shell "ps -A | grep '$process_name' | awk '{print \$2}'" | tr -d '\r' || echo "")

    if [ -z "$pids" ]; then
        log_info "No processes matching '$process_name' found"
        return 0
    fi

    log_info "Found PIDs: $pids"

    for pid in $pids; do
        adb shell "kill $pid" 2>/dev/null || true
    done

    sleep 1

    # Force kill if still running
    pids=$(adb shell "ps -A | grep '$process_name' | awk '{print \$2}'" | tr -d '\r' || echo "")
    if [ -n "$pids" ]; then
        log_warn "Force killing: $pids"
        for pid in $pids; do
            adb shell "kill -9 $pid" 2>/dev/null || true
        done
    fi
}

# Check if process is running on Android device
adb_process_exists() {
    local process_name="$1"

    if adb shell "ps -A | grep -q '$process_name'"; then
        return 0
    else
        return 1
    fi
}

# Get PID of process on Android device
adb_get_pid() {
    local process_name="$1"
    local pid

    pid=$(adb shell "ps -A | grep '$process_name' | head -1 | awk '{print \$2}'" | tr -d '\r')

    if [ -n "$pid" ]; then
        echo "$pid"
        return 0
    else
        return 1
    fi
}

# Create directory on Android device
adb_mkdir() {
    local dir="$1"
    adb shell "mkdir -p '$dir'" 2>/dev/null || true
}

# Remove directory/file on Android device
adb_rm() {
    local path="$1"
    adb shell "rm -rf '$path'" 2>/dev/null || true
}

# Check if file exists on Android device
adb_file_exists() {
    local file="$1"

    if adb shell "[ -f '$file' ]" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Get file size on Android device
adb_file_size() {
    local file="$1"
    local size

    size=$(adb shell "stat -c %s '$file' 2>/dev/null" | tr -d '\r')

    if [ -n "$size" ]; then
        echo "$size"
        return 0
    else
        echo "0"
        return 1
    fi
}

# Check prerequisites for Android e2e tests
check_android_prerequisites() {
    log_info "=== Checking Android Prerequisites ==="

    local failed=0

    check_adb || failed=1
    check_android_device || failed=1
    check_android_version || failed=1
    check_android_kernel || failed=1
    check_android_arch || failed=1
    check_android_root || failed=1

    # SELinux check (warning only)
    if ! check_selinux; then
        log_warn "Attempting to set SELinux to permissive mode..."
        set_selinux_permissive || true
    fi

    if [ $failed -eq 1 ]; then
        log_error "Prerequisites check failed"
        return 1
    fi

    log_success "All prerequisites met"
    return 0
}

# Cleanup function template
cleanup_handler() {
    log_info "Cleaning up..."
}

# Setup trap for cleanup
setup_cleanup_trap() {
    trap cleanup_handler EXIT INT TERM
}

# Verify text in output file
verify_text_in_output() {
    local output_file="$1"
    local search_text="$2"
    local description="${3:-text}"

    if [ ! -f "$output_file" ]; then
        log_error "Output file not found: $output_file"
        return 1
    fi

    if grep -q "$search_text" "$output_file"; then
        log_success "Found $description in output"
        return 0
    else
        log_error "Did not find $description in output"
        log_info "Output file content (first 50 lines):"
        head -50 "$output_file"
        return 1
    fi
}

# Build ecapture for Android
build_ecapture_android() {
    local binary="$1"

    if [ -x "$binary" ]; then
        log_info "ecapture Android binary already exists: $binary"
        return 0
    fi

    log_info "Building ecapture for Android..."

    local root_dir
    root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../../ && pwd)"
    cd "$root_dir"

    if is_macos; then
        log_error "Cannot build Android binary on macOS. Please build on Linux."
        log_info "Use: ssh cfc4n@172.16.71.128 'cd /home/cfc4n/project/ecapture && ANDROID=1 make nocore'"
        return 1
    fi

    if ANDROID=1 make nocore -j 4 >/dev/null 2>&1; then
        log_success "Build succeeded with 'ANDROID=1 make nocore'"
        return 0
    fi

    log_error "Failed to build ecapture for Android"
    return 1
}

# Wait for Android device to be ready
wait_for_device() {
    log_info "Waiting for device..."
    adb wait-for-device
    sleep 2
    log_success "Device ready"
}

# Get Android device property
get_device_prop() {
    local prop="$1"
    adb shell getprop "$prop" | tr -d '\r'
}

# Check if command exists on Android device
adb_command_exists() {
    local cmd="$1"

    if adb shell "command -v '$cmd' >/dev/null 2>&1" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

log_info "Android common utilities loaded"
