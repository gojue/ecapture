#!/usr/bin/env bash
# File: test/e2e/android/android_tls_e2e_test.sh
# End-to-end test for ecapture TLS module on Android (OpenSSL/BoringSSL)
# Requirements: Android 15+, ARM64, Kernel 5.5+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/android/common_android.sh
source "$SCRIPT_DIR/common_android.sh"

# Test configuration
TEST_NAME="Android TLS E2E Test"
TEST_URL="https://www.google.com"
DEVICE_ECAPTURE="/data/local/tmp/ecapture"
DEVICE_OUTPUT_DIR="/data/local/tmp/ecapture_test"
LOCAL_OUTPUT_DIR="/tmp/ecapture_android_tls_$$"

# Test results
TEST_FAILED=0
TESTS_PASSED=0
TESTS_TOTAL=0

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="

    # Kill ecapture on device
    adb_kill_by_name "ecapture" || true

    # Pull logs if test failed
    if [ "$TEST_FAILED" = "1" ]; then
        log_error "Test failed. Pulling logs from device..."
        mkdir -p "$LOCAL_OUTPUT_DIR"
        adb_pull "$DEVICE_OUTPUT_DIR/ecapture.log" "$LOCAL_OUTPUT_DIR/ecapture.log" 2>/dev/null || true
        adb_pull "$DEVICE_OUTPUT_DIR/curl.log" "$LOCAL_OUTPUT_DIR/curl.log" 2>/dev/null || true

        if [ -f "$LOCAL_OUTPUT_DIR/ecapture.log" ]; then
            log_info "=== eCapture Log (last 100 lines) ==="
            tail -100 "$LOCAL_OUTPUT_DIR/ecapture.log"
        fi
    fi

    # Clean up device
    adb_rm "$DEVICE_OUTPUT_DIR"

    # Clean up local
    rm -rf "$LOCAL_OUTPUT_DIR"

    # Show test summary
    log_info "=== Test Summary ==="
    log_info "Tests passed: $TESTS_PASSED / $TESTS_TOTAL"

    if [ "$TEST_FAILED" = "1" ]; then
        log_error "Some tests FAILED"
    else
        log_success "All tests PASSED"
    fi
}

# Setup trap
setup_cleanup_trap

# Test text mode - captures plaintext directly
test_text_mode() {
    log_info "=== Test 1: Text Mode TLS Capture ==="
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local test_log="$DEVICE_OUTPUT_DIR/text_mode.log"

    # Start ecapture in text mode (background)
    log_info "Starting ecapture in text mode on device..."
    adb shell "cd $DEVICE_OUTPUT_DIR && nohup $DEVICE_ECAPTURE tls -m text > text_mode.log 2>&1 &"

    # Wait for initialization
    sleep 5

    # Check if ecapture is running
    if ! adb_process_exists "ecapture"; then
        log_error "eCapture process not running"
        TEST_FAILED=1
        return 1
    fi

    log_success "eCapture started successfully"

    # Make HTTPS request using curl on device
    log_info "Making HTTPS request to $TEST_URL..."
    adb shell "curl -s -o /dev/null '$TEST_URL' 2>$DEVICE_OUTPUT_DIR/curl.log" || true

    # Wait for capture
    sleep 3

    # Stop ecapture
    adb_kill_by_name "ecapture"
    sleep 2

    # Pull log file
    mkdir -p "$LOCAL_OUTPUT_DIR"
    if ! adb_pull "$test_log" "$LOCAL_OUTPUT_DIR/text_mode.log"; then
        log_error "Failed to pull log file"
        TEST_FAILED=1
        return 1
    fi

    # Verify results
    local log_size
    log_size=$(stat -f%z "$LOCAL_OUTPUT_DIR/text_mode.log" 2>/dev/null || stat -c%s "$LOCAL_OUTPUT_DIR/text_mode.log" 2>/dev/null || echo "0")

    log_info "Text mode log size: $log_size bytes"

    if [ "$log_size" -lt 100 ]; then
        log_error "Log file too small, capture may have failed"
        TEST_FAILED=1
        return 1
    fi

    # Check for HTTP plaintext indicators
    if grep -iq "GET\|POST\|HTTP\|Host:" "$LOCAL_OUTPUT_DIR/text_mode.log"; then
        log_success "✓ Test 1 PASSED: Found HTTP plaintext in output"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "✗ Test 1 FAILED: No HTTP plaintext found"
        log_info "Log content (first 50 lines):"
        head -50 "$LOCAL_OUTPUT_DIR/text_mode.log"
        TEST_FAILED=1
        return 1
    fi
}

# Test pcap mode - captures packets
test_pcap_mode() {
    log_info "=== Test 2: PCAP Mode TLS Capture ==="
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local test_pcap="$DEVICE_OUTPUT_DIR/capture.pcapng"
    local test_log="$DEVICE_OUTPUT_DIR/pcap_mode.log"

    # Start ecapture in pcap mode
    log_info "Starting ecapture in pcap mode on device..."
    adb shell "cd $DEVICE_OUTPUT_DIR && nohup $DEVICE_ECAPTURE tls -m pcap -w capture.pcapng > pcap_mode.log 2>&1 &"

    # Wait for initialization
    sleep 5

    # Check if ecapture is running
    if ! adb_process_exists "ecapture"; then
        log_error "eCapture process not running"
        TEST_FAILED=1
        return 1
    fi

    log_success "eCapture started in pcap mode"

    # Make HTTPS request
    log_info "Making HTTPS request to $TEST_URL..."
    adb shell "curl -s -o /dev/null '$TEST_URL'" || true

    # Wait for capture
    sleep 3

    # Stop ecapture
    adb_kill_by_name "ecapture"
    sleep 2

    # Check if pcap file exists on device
    if ! adb_file_exists "$test_pcap"; then
        log_error "PCAP file not created on device"
        TEST_FAILED=1
        return 1
    fi

    local pcap_size
    pcap_size=$(adb_file_size "$test_pcap")
    log_info "PCAP file size: $pcap_size bytes"

    if [ "$pcap_size" -lt 100 ]; then
        log_error "PCAP file too small"
        TEST_FAILED=1
        return 1
    fi

    log_success "✓ Test 2 PASSED: PCAP file created successfully"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    return 0
}

# Test with PID filter
test_pid_filter() {
    log_info "=== Test 3: PID Filter Test ==="
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local test_log="$DEVICE_OUTPUT_DIR/pid_filter.log"

    # Start a curl process in background and get its PID
    log_info "Starting curl in background..."
    adb shell "curl -s '$TEST_URL' > /dev/null &"
    sleep 1

    local curl_pid
    curl_pid=$(adb_get_pid "curl" || echo "")

    if [ -z "$curl_pid" ]; then
        log_warn "Could not get curl PID, skipping PID filter test"
        return 0
    fi

    log_info "Curl PID: $curl_pid"

    # Start ecapture with PID filter
    log_info "Starting ecapture with PID filter..."
    adb shell "cd $DEVICE_OUTPUT_DIR && nohup $DEVICE_ECAPTURE tls -m text --pid=$curl_pid > pid_filter.log 2>&1 &"

    sleep 3

    # Make another request
    adb shell "curl -s -o /dev/null '$TEST_URL'" || true

    sleep 2

    # Stop ecapture
    adb_kill_by_name "ecapture"
    adb_kill_by_name "curl"

    sleep 1

    # Pull and check log
    mkdir -p "$LOCAL_OUTPUT_DIR"
    adb_pull "$test_log" "$LOCAL_OUTPUT_DIR/pid_filter.log" 2>/dev/null || true

    if [ -f "$LOCAL_OUTPUT_DIR/pid_filter.log" ]; then
        local log_size
        log_size=$(stat -f%z "$LOCAL_OUTPUT_DIR/pid_filter.log" 2>/dev/null || stat -c%s "$LOCAL_OUTPUT_DIR/pid_filter.log" 2>/dev/null || echo "0")

        if [ "$log_size" -gt 50 ]; then
            log_success "✓ Test 3 PASSED: PID filter test completed"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        fi
    fi

    log_warn "PID filter test inconclusive"
    return 0
}

# Main test function
main() {
    log_info "=== $TEST_NAME ==="
    log_info "Target URL: $TEST_URL"

    # Check prerequisites
    log_info "=== Step 1: Prerequisites Check ==="
    if ! check_android_prerequisites; then
        log_error "Prerequisites not met"
        exit 1
    fi

    # Check if curl is available on device
    log_info "Checking for curl on device..."
    if ! adb_command_exists "curl"; then
        log_error "curl not found on Android device"
        log_info "Please install curl or use a device with curl pre-installed"
        exit 1
    fi
    log_success "curl is available"

    # Create output directory on device
    log_info "=== Step 2: Setup Test Environment ==="
    adb_mkdir "$DEVICE_OUTPUT_DIR"

    # Check if ecapture binary exists locally
    local local_binary="$ROOT_DIR/bin/ecapture"
    if [ ! -f "$local_binary" ]; then
        log_error "ecapture binary not found at $local_binary"
        log_info "Please build for Android: ANDROID=1 make nocore"
        exit 1
    fi

    log_info "Found ecapture binary: $local_binary"

    # Push ecapture to device
    log_info "=== Step 3: Deploy ecapture to Device ==="
    if ! adb_push "$local_binary" "$DEVICE_ECAPTURE"; then
        log_error "Failed to push ecapture to device"
        exit 1
    fi

    # Verify binary on device
    if ! adb_file_exists "$DEVICE_ECAPTURE"; then
        log_error "ecapture binary not found on device"
        exit 1
    fi

    log_success "ecapture deployed successfully"

    # Run tests
    log_info "=== Step 4: Run Tests ==="

    test_text_mode || true
    sleep 2

    test_pcap_mode || true
    sleep 2

    test_pid_filter || true

    # Summary
    log_info "=== Test Execution Complete ==="

    if [ "$TESTS_PASSED" -eq "$TESTS_TOTAL" ] && [ "$TESTS_TOTAL" -gt 0 ]; then
        log_success "All $TESTS_TOTAL tests PASSED"
        exit 0
    elif [ "$TESTS_PASSED" -gt 0 ]; then
        log_warn "$TESTS_PASSED / $TESTS_TOTAL tests passed"
        exit 1
    else
        log_error "All tests FAILED"
        exit 1
    fi
}

main
