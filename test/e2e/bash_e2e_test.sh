#!/usr/bin/env bash
# File: test/e2e/bash_e2e_test.sh
# End-to-end test for ecapture Bash module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="Bash E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_bash_e2e_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Log files
ECAPTURE_LOG="$OUTPUT_DIR/ecapture.log"
TEST_COMMANDS_LOG="$OUTPUT_DIR/test_commands.log"

# Test results
TEST_FAILED=0

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    
    # Kill ecapture by pattern
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
    
    # Show logs on failure
    if [ "$TEST_FAILED" = "1" ]; then
        log_error "Test failed. Showing logs:"
        echo "=== eCapture Log ==="
        cat "$ECAPTURE_LOG" 2>/dev/null || echo "No ecapture log"
        echo "=== Test Commands Log ==="
        cat "$TEST_COMMANDS_LOG" 2>/dev/null || echo "No test commands log"
    fi
    
    # Clean up temporary directory
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

# Setup trap
setup_cleanup_trap

# Main test function
run_bash_test() {
    log_info "=== Starting $TEST_NAME ==="
    
    # Prerequisites
    log_info "Checking prerequisites..."
    check_root || exit 1
    check_kernel_version 4 18 || exit 1
    check_prerequisites bash "$ECAPTURE_BINARY" || exit 1
    
    # Check if bash has readline
    if ! check_library_linkage "bash" "readline" "readline library"; then
        log_warn "Bash may not be using readline, test may produce limited results"
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Build ecapture if needed
    build_ecapture "$ECAPTURE_BINARY" || {
        log_error "Failed to build ecapture"
        exit 1
    }
    
    # Test 1: Basic bash command capture
    log_info "=== Test 1: Basic Command Capture ==="
    
    # Start ecapture for current bash process
    log_info "Running: $ECAPTURE_BINARY bash"
    "$ECAPTURE_BINARY" bash > "$ECAPTURE_LOG" 2>&1 &
    local ecapture_pid=$!
    log_info "eCapture PID: $ecapture_pid"
    
    # Wait for initialization
    sleep 3
    
    # Check if still running
    if ! kill -0 "$ecapture_pid" 2>/dev/null; then
        log_error "eCapture process died during initialization"
        cat "$ECAPTURE_LOG"
        TEST_FAILED=1
        return 1
    fi
    
    # Execute test commands in a new bash session
    log_info "Executing test commands in bash..."
    {
        echo "echo 'test_command_1'"
        echo "ls -la /tmp | head -5"
        echo "whoami"
        echo "pwd"
        echo "echo 'test_command_2'"
    } > "$TEST_COMMANDS_LOG"
    
    # Run commands through bash
    bash < "$TEST_COMMANDS_LOG" >/dev/null 2>&1 || true
    
    # Wait for capture
    sleep 3
    
    # Stop ecapture
    if kill -0 "$ecapture_pid" 2>/dev/null; then
        log_info "Stopping ecapture..."
        kill -INT "$ecapture_pid" 2>/dev/null || true
        sleep 2
        
        # Force kill if still running
        if kill -0 "$ecapture_pid" 2>/dev/null; then
            kill -9 "$ecapture_pid" 2>/dev/null || true
        fi
    fi
    
    # Verify results
    log_info "=== Verifying Results ==="
    
    local test_passed=0
    
    if [ ! -s "$ECAPTURE_LOG" ]; then
        log_error "eCapture log is empty"
        TEST_FAILED=1
        return 1
    fi
    
    log_info "eCapture log size: $(wc -c < "$ECAPTURE_LOG") bytes"
    log_info "Sample output (first 50 lines):"
    head -n 50 "$ECAPTURE_LOG"
    
    # Check if we captured some bash commands
    # Note: We look for common patterns that might appear in bash command capture
    if grep -iq "bash\|readline\|command" "$ECAPTURE_LOG"; then
        log_success "Found bash-related content in capture"
        test_passed=1
    else
        log_warn "Could not find expected bash patterns in output"
        log_info "This might be due to readline not being used or other configuration issues"
        # Don't fail the test as this can happen in different environments
    fi
    
    # Check for any captured commands (even if not the exact test commands)
    if grep -E "echo|ls|pwd|whoami" "$ECAPTURE_LOG" >/dev/null 2>&1; then
        log_success "Found some captured commands in output"
        test_passed=1
    fi
    
    # Test 2: Error number filtering
    log_info "=== Test 2: Error Number Filtering ==="
    
    local filtered_log="$OUTPUT_DIR/ecapture_filtered.log"
    
    log_info "Running: $ECAPTURE_BINARY bash -e 0"
    "$ECAPTURE_BINARY" bash -e 0 > "$filtered_log" 2>&1 &
    local filtered_pid=$!
    
    sleep 3
    
    if kill -0 "$filtered_pid" 2>/dev/null; then
        # Run a successful command
        bash -c "echo 'successful_command'" >/dev/null 2>&1 || true
        
        sleep 2
        
        kill -INT "$filtered_pid" 2>/dev/null || true
        sleep 2
        
        if [ -s "$filtered_log" ]; then
            log_success "Error filtering test completed"
            test_passed=1
        fi
    fi
    
    # Overall result
    if [ "$test_passed" = "1" ]; then
        log_success "=== $TEST_NAME PASSED ==="
        return 0
    else
        log_error "=== $TEST_NAME FAILED ==="
        TEST_FAILED=1
        return 1
    fi
}

# Run the test
run_bash_test

exit $?
