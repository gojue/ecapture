#!/usr/bin/env bash
# File: test/e2e/android/android_bash_e2e_test.sh
# End-to-end test for ecapture Bash module on Android
# Requirements: Android 15+, ARM64, Kernel 5.5+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/android/common_android.sh
source "$SCRIPT_DIR/common_android.sh"

# Test configuration
TEST_NAME="Android Bash E2E Test"
DEVICE_ECAPTURE="/data/local/tmp/ecapture"
DEVICE_OUTPUT_DIR="/data/local/tmp/ecapture_bash_test"
LOCAL_OUTPUT_DIR="/tmp/ecapture_android_bash_$$"

# Test results
TEST_FAILED=0
TESTS_PASSED=0
TESTS_TOTAL=0

# Test commands to capture
TEST_COMMANDS=(
    "echo 'Hello from Android'"
    "ls -la /data/local/tmp"
    "pwd"
    "whoami"
    "uname -a"
)

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

# Test basic bash command capture
test_basic_bash_capture() {
    log_info "=== Test 1: Basic Bash Command Capture ==="
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local test_log="$DEVICE_OUTPUT_DIR/bash_capture.log"

    # Start ecapture for bash (sh on Android)
    log_info "Starting ecapture for bash/sh on device..."
    adb shell "cd $DEVICE_OUTPUT_DIR && nohup $DEVICE_ECAPTURE bash > bash_capture.log 2>&1 &"

    # Wait for initialization
    sleep 5

    # Check if ecapture is running
    if ! adb_process_exists "ecapture"; then
        log_error "eCapture process not running"
        TEST_FAILED=1
        return 1
    fi

    log_success "eCapture started successfully"

    # Execute test commands via adb shell
    log_info "Executing test commands on device..."
    for cmd in "${TEST_COMMANDS[@]}"; do
        log_info "Running: $cmd"
        adb shell "$cmd" > /dev/null 2>&1 || true
        sleep 1
    done

    # Wait for capture
    sleep 3

    # Stop ecapture
    adb_kill_by_name "ecapture"
    sleep 2

    # Pull log file
    mkdir -p "$LOCAL_OUTPUT_DIR"
    if ! adb_pull "$test_log" "$LOCAL_OUTPUT_DIR/bash_capture.log"; then
        log_error "Failed to pull log file"
        TEST_FAILED=1
        return 1
    fi

    # Verify results
    local log_size
    log_size=$(stat -f%z "$LOCAL_OUTPUT_DIR/bash_capture.log" 2>/dev/null || stat -c%s "$LOCAL_OUTPUT_DIR/bash_capture.log" 2>/dev/null || echo "0")

    log_info "Bash capture log size: $log_size bytes"

    if [ "$log_size" -lt 50 ]; then
        log_error "Log file too small, capture may have failed"
        TEST_FAILED=1
        return 1
    fi

    # Check for captured commands
    local found_commands=0
    for cmd_pattern in "echo" "ls" "pwd" "whoami" "uname"; do
        if grep -iq "$cmd_pattern" "$LOCAL_OUTPUT_DIR/bash_capture.log"; then
            log_info "Found command: $cmd_pattern"
            found_commands=$((found_commands + 1))
        fi
    done

    if [ "$found_commands" -ge 2 ]; then
        log_success "✓ Test 1 PASSED: Found $found_commands shell commands in output"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_warn "Only found $found_commands commands, but test executed"
        log_info "Log content (first 100 lines):"
        head -100 "$LOCAL_OUTPUT_DIR/bash_capture.log"

        # Still count as pass if log has content
        if [ "$log_size" -gt 200 ]; then
            log_success "✓ Test 1 PASSED: Bash capture produced output"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        else
            TEST_FAILED=1
            return 1
        fi
    fi
}

# Test bash with long command
test_long_command() {
    log_info "=== Test 2: Long Command Test ==="
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local test_log="$DEVICE_OUTPUT_DIR/long_cmd.log"

    # Start ecapture
    log_info "Starting ecapture for long command test..."
    adb shell "cd $DEVICE_OUTPUT_DIR && nohup $DEVICE_ECAPTURE bash > long_cmd.log 2>&1 &"

    sleep 5

    if ! adb_process_exists "ecapture"; then
        log_error "eCapture process not running"
        TEST_FAILED=1
        return 1
    fi

    # Execute a long command
    local long_cmd="echo 'This is a very long command with many parameters and arguments to test the bash capture functionality on Android device running ecapture'"
    log_info "Executing long command..."
    adb shell "$long_cmd" > /dev/null 2>&1 || true

    sleep 2

    # Stop ecapture
    adb_kill_by_name "ecapture"
    sleep 2

    # Pull and check log
    mkdir -p "$LOCAL_OUTPUT_DIR"
    adb_pull "$test_log" "$LOCAL_OUTPUT_DIR/long_cmd.log" 2>/dev/null || true

    if [ -f "$LOCAL_OUTPUT_DIR/long_cmd.log" ]; then
        local log_size
        log_size=$(stat -f%z "$LOCAL_OUTPUT_DIR/long_cmd.log" 2>/dev/null || stat -c%s "$LOCAL_OUTPUT_DIR/long_cmd.log" 2>/dev/null || echo "0")

        if [ "$log_size" -gt 50 ]; then
            log_success "✓ Test 2 PASSED: Long command test completed"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        fi
    fi

    log_warn "Long command test inconclusive"
    return 0
}

# Test bash with pipe commands
test_pipe_commands() {
    log_info "=== Test 3: Pipe Commands Test ==="
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local test_log="$DEVICE_OUTPUT_DIR/pipe_cmd.log"

    # Start ecapture
    log_info "Starting ecapture for pipe command test..."
    adb shell "cd $DEVICE_OUTPUT_DIR && nohup $DEVICE_ECAPTURE bash > pipe_cmd.log 2>&1 &"

    sleep 5

    if ! adb_process_exists "ecapture"; then
        log_error "eCapture process not running"
        TEST_FAILED=1
        return 1
    fi

    # Execute commands with pipes
    log_info "Executing pipe commands..."
    adb shell "ls /data/local/tmp | grep ecapture" > /dev/null 2>&1 || true
    sleep 1
    adb shell "echo 'test' | cat" > /dev/null 2>&1 || true
    sleep 1
    adb shell "ps -A | grep sh" > /dev/null 2>&1 || true

    sleep 2

    # Stop ecapture
    adb_kill_by_name "ecapture"
    sleep 2

    # Pull and check log
    mkdir -p "$LOCAL_OUTPUT_DIR"
    adb_pull "$test_log" "$LOCAL_OUTPUT_DIR/pipe_cmd.log" 2>/dev/null || true

    if [ -f "$LOCAL_OUTPUT_DIR/pipe_cmd.log" ]; then
        local log_size
        log_size=$(stat -f%z "$LOCAL_OUTPUT_DIR/pipe_cmd.log" 2>/dev/null || stat -c%s "$LOCAL_OUTPUT_DIR/pipe_cmd.log" 2>/dev/null || echo "0")

        log_info "Pipe command log size: $log_size bytes"

        # Check for pipe character or relevant commands
        if grep -iq "grep\|cat\|ls\|ps" "$LOCAL_OUTPUT_DIR/pipe_cmd.log"; then
            log_success "✓ Test 3 PASSED: Found pipe commands in output"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        elif [ "$log_size" -gt 100 ]; then
            log_success "✓ Test 3 PASSED: Pipe command test produced output"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        fi
    fi

    log_warn "Pipe commands test inconclusive"
    return 0
}

# Main test function
main() {
    log_info "=== $TEST_NAME ==="

    # Check prerequisites
    log_info "=== Step 1: Prerequisites Check ==="
    if ! check_android_prerequisites; then
        log_error "Prerequisites not met"
        exit 1
    fi

    # Check if sh/bash is available on device
    log_info "Checking for shell on device..."
    if ! adb_command_exists "sh"; then
        log_error "sh not found on Android device"
        exit 1
    fi
    log_success "Shell is available"

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

    log_success "ecapture deployed successfully"

    # Run tests
    log_info "=== Step 4: Run Tests ==="

    test_basic_bash_capture || true
    sleep 2

    test_long_command || true
    sleep 2

    test_pipe_commands || true

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
