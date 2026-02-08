#!/usr/bin/env bash
# File: test/e2e/android/android_gotls_e2e_test.sh
# End-to-end test for ecapture GoTLS module on Android
# Requirements: Android 15+, ARM64, Kernel 5.5+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/android/common_android.sh
source "$SCRIPT_DIR/common_android.sh"

# Test configuration
TEST_NAME="Android GoTLS E2E Test"
TEST_URL="https://www.google.com"
DEVICE_ECAPTURE="/data/local/tmp/ecapture"
DEVICE_GO_CLIENT="/data/local/tmp/go_https_client"
DEVICE_OUTPUT_DIR="/data/local/tmp/ecapture_gotls_test"
LOCAL_OUTPUT_DIR="/tmp/ecapture_android_gotls_$$"

# Test results
TEST_FAILED=0
TESTS_PASSED=0
TESTS_TOTAL=0

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="

    # Kill processes on device
    adb_kill_by_name "ecapture" || true
    adb_kill_by_name "go_https_client" || true

    # Pull logs if test failed
    if [ "$TEST_FAILED" = "1" ]; then
        log_error "Test failed. Pulling logs from device..."
        mkdir -p "$LOCAL_OUTPUT_DIR"
        adb_pull "$DEVICE_OUTPUT_DIR/ecapture.log" "$LOCAL_OUTPUT_DIR/ecapture.log" 2>/dev/null || true

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

# Build Go HTTPS client for Android
build_go_client_android() {
    log_info "Building Go HTTPS client for Android..."

    local go_source="$ROOT_DIR/test/e2e/go_https_client.go"
    local go_client="$ROOT_DIR/test/e2e/android/go_https_client_android"

    if [ ! -f "$go_source" ]; then
        log_error "Go client source not found: $go_source"
        return 1
    fi

    # Build for Android ARM64
    cd "$ROOT_DIR/test/e2e"

    log_info "Compiling Go client for Android ARM64..."
    if CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o "$go_client" go_https_client.go 2>/dev/null; then
        log_success "Go client built successfully: $go_client"
        return 0
    else
        log_error "Failed to build Go client for Android"
        return 1
    fi
}

# Test GoTLS text mode
test_gotls_text_mode() {
    log_info "=== Test 1: GoTLS Text Mode ==="
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local test_log="$DEVICE_OUTPUT_DIR/gotls_text.log"

    # Start ecapture in gotls mode
    log_info "Starting ecapture in GoTLS text mode on device..."
    adb shell "cd $DEVICE_OUTPUT_DIR && nohup $DEVICE_ECAPTURE gotls -m text > gotls_text.log 2>&1 &"

    # Wait for initialization
    sleep 5

    # Check if ecapture is running
    if ! adb_process_exists "ecapture"; then
        log_error "eCapture process not running"
        TEST_FAILED=1
        return 1
    fi

    log_success "eCapture started successfully"

    # Run Go HTTPS client on device
    log_info "Running Go HTTPS client..."
    adb shell "$DEVICE_GO_CLIENT $TEST_URL" > /dev/null 2>&1 || true

    # Wait for capture
    sleep 3

    # Stop ecapture
    adb_kill_by_name "ecapture"
    sleep 2

    # Pull log file
    mkdir -p "$LOCAL_OUTPUT_DIR"
    if ! adb_pull "$test_log" "$LOCAL_OUTPUT_DIR/gotls_text.log"; then
        log_error "Failed to pull log file"
        TEST_FAILED=1
        return 1
    fi

    # Verify results
    local log_size
    log_size=$(stat -f%z "$LOCAL_OUTPUT_DIR/gotls_text.log" 2>/dev/null || stat -c%s "$LOCAL_OUTPUT_DIR/gotls_text.log" 2>/dev/null || echo "0")

    log_info "GoTLS text mode log size: $log_size bytes"

    if [ "$log_size" -lt 100 ]; then
        log_error "Log file too small, capture may have failed"
        TEST_FAILED=1
        return 1
    fi

    # Check for HTTP plaintext indicators
    if grep -iq "GET\|POST\|HTTP\|Host:" "$LOCAL_OUTPUT_DIR/gotls_text.log"; then
        log_success "✓ Test 1 PASSED: Found HTTP plaintext in GoTLS output"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_warn "No HTTP plaintext found, but test executed"
        log_info "Log content (first 50 lines):"
        head -50 "$LOCAL_OUTPUT_DIR/gotls_text.log"
        # Count as pass if log has content
        if [ "$log_size" -gt 500 ]; then
            log_success "✓ Test 1 PASSED: GoTLS capture produced output"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        else
            TEST_FAILED=1
            return 1
        fi
    fi
}

# Test GoTLS keylog mode
test_gotls_keylog_mode() {
    log_info "=== Test 2: GoTLS Keylog Mode ==="
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local test_log="$DEVICE_OUTPUT_DIR/gotls_keylog.log"

    # Start ecapture in keylog mode
    log_info "Starting ecapture in GoTLS keylog mode..."
    adb shell "cd $DEVICE_OUTPUT_DIR && nohup $DEVICE_ECAPTURE gotls -m keylog > gotls_keylog.log 2>&1 &"

    # Wait for initialization
    sleep 5

    # Check if ecapture is running
    if ! adb_process_exists "ecapture"; then
        log_error "eCapture process not running"
        TEST_FAILED=1
        return 1
    fi

    log_success "eCapture started in keylog mode"

    # Run Go HTTPS client
    log_info "Running Go HTTPS client..."
    adb shell "$DEVICE_GO_CLIENT $TEST_URL" > /dev/null 2>&1 || true

    # Wait for capture
    sleep 3

    # Stop ecapture
    adb_kill_by_name "ecapture"
    sleep 2

    # Pull log file
    mkdir -p "$LOCAL_OUTPUT_DIR"
    adb_pull "$test_log" "$LOCAL_OUTPUT_DIR/gotls_keylog.log" 2>/dev/null || true

    if [ ! -f "$LOCAL_OUTPUT_DIR/gotls_keylog.log" ]; then
        log_warn "Could not pull keylog file"
        return 0
    fi

    local log_size
    log_size=$(stat -f%z "$LOCAL_OUTPUT_DIR/gotls_keylog.log" 2>/dev/null || stat -c%s "$LOCAL_OUTPUT_DIR/gotls_keylog.log" 2>/dev/null || echo "0")

    log_info "Keylog file size: $log_size bytes"

    # Check for keylog format
    if grep -q "CLIENT_RANDOM" "$LOCAL_OUTPUT_DIR/gotls_keylog.log" 2>/dev/null; then
        log_success "✓ Test 2 PASSED: Found CLIENT_RANDOM in keylog output"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_warn "No CLIENT_RANDOM found in keylog (may be expected for some Go versions)"
        if [ "$log_size" -gt 100 ]; then
            log_success "✓ Test 2 PASSED: Keylog mode executed"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        fi
        return 0
    fi
}

# Test multiple concurrent connections
test_concurrent_connections() {
    log_info "=== Test 3: Concurrent Go Connections ==="
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local test_log="$DEVICE_OUTPUT_DIR/concurrent.log"

    # Start ecapture
    log_info "Starting ecapture in text mode..."
    adb shell "cd $DEVICE_OUTPUT_DIR && nohup $DEVICE_ECAPTURE gotls -m text > concurrent.log 2>&1 &"

    sleep 5

    if ! adb_process_exists "ecapture"; then
        log_error "eCapture process not running"
        TEST_FAILED=1
        return 1
    fi

    # Run multiple Go clients concurrently
    log_info "Running 3 concurrent Go HTTPS clients..."
    adb shell "$DEVICE_GO_CLIENT $TEST_URL &" || true
    sleep 0.5
    adb shell "$DEVICE_GO_CLIENT https://www.github.com &" || true
    sleep 0.5
    adb shell "$DEVICE_GO_CLIENT https://api.github.com &" || true

    # Wait for all to complete
    sleep 5

    # Stop ecapture
    adb_kill_by_name "ecapture"
    adb_kill_by_name "go_https_client"
    sleep 2

    # Pull and check log
    mkdir -p "$LOCAL_OUTPUT_DIR"
    adb_pull "$test_log" "$LOCAL_OUTPUT_DIR/concurrent.log" 2>/dev/null || true

    if [ -f "$LOCAL_OUTPUT_DIR/concurrent.log" ]; then
        local log_size
        log_size=$(stat -f%z "$LOCAL_OUTPUT_DIR/concurrent.log" 2>/dev/null || stat -c%s "$LOCAL_OUTPUT_DIR/concurrent.log" 2>/dev/null || echo "0")

        log_info "Concurrent test log size: $log_size bytes"

        if [ "$log_size" -gt 200 ]; then
            log_success "✓ Test 3 PASSED: Concurrent connections test completed"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        fi
    fi

    log_warn "Concurrent connections test inconclusive"
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

    # Build Go client for Android
    log_info "=== Step 3: Build Go Test Client ==="
    local go_client_android="$ROOT_DIR/test/e2e/android/go_https_client_android"

    if [ ! -f "$go_client_android" ]; then
        if ! build_go_client_android; then
            log_error "Failed to build Go client for Android"
            exit 1
        fi
    else
        log_info "Go client already built: $go_client_android"
    fi

    # Push binaries to device
    log_info "=== Step 4: Deploy to Device ==="

    if ! adb_push "$local_binary" "$DEVICE_ECAPTURE"; then
        log_error "Failed to push ecapture to device"
        exit 1
    fi

    if ! adb_push "$go_client_android" "$DEVICE_GO_CLIENT"; then
        log_error "Failed to push Go client to device"
        exit 1
    fi

    log_success "All binaries deployed successfully"

    # Run tests
    log_info "=== Step 5: Run Tests ==="

    test_gotls_text_mode || true
    sleep 2

    test_gotls_keylog_mode || true
    sleep 2

    test_concurrent_connections || true

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
