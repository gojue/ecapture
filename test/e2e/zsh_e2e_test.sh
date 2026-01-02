#!/usr/bin/env bash
# File: test/e2e/zsh_e2e_test.sh
# End-to-end test for ecapture Zsh module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="Zsh E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_zsh_e2e_$$"
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
    kill_by_pattern "$ECAPTURE_BINARY.*zsh" || true
    
    # Show logs on failure
    if [ "$TEST_FAILED" = "1" ]; then
        log_error "Test failed. Showing logs:"
        echo "=== eCapture Log ==="
        cat "$ECAPTURE_LOG" 2>/dev/null || echo "No ecapture log"
    fi
    
    # Clean up temporary directory
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

# Setup trap
setup_cleanup_trap

# Main test function
run_zsh_test() {
    log_info "=== Starting $TEST_NAME ==="
    
    # Prerequisites
    log_info "Checking prerequisites..."
    check_root || exit 1
    check_kernel_version 4 18 || exit 1
    
    # Check if zsh is installed
    if ! command_exists zsh; then
        log_warn "zsh is not installed, skipping zsh test"
        log_info "To install zsh: sudo apt-get install zsh (Debian/Ubuntu) or sudo yum install zsh (RHEL/CentOS)"
        exit 0
    fi
    
    check_prerequisites "$ECAPTURE_BINARY" || exit 1
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Build ecapture if needed
    build_ecapture "$ECAPTURE_BINARY" || {
        log_error "Failed to build ecapture"
        exit 1
    }
    
    # Test: Basic zsh command capture
    log_info "=== Test: Zsh Command Capture ==="
    
    # Start ecapture for zsh
    log_info "Running: $ECAPTURE_BINARY zsh"
    "$ECAPTURE_BINARY" zsh > "$ECAPTURE_LOG" 2>&1 &
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
    
    # Execute test commands in zsh
    log_info "Executing test commands in zsh..."
    zsh -c "
        echo 'zsh_test_command_1'
        ls -la /tmp | head -3
        whoami
        pwd
        echo 'zsh_test_command_2'
    " >/dev/null 2>&1 || true
    
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
    
    # Check if we captured some zsh commands
    if grep -iq "zsh" "$ECAPTURE_LOG"; then
        log_success "Found zsh-related content in capture"
        test_passed=1
    else
        log_warn "Could not find zsh patterns in output"
    fi
    
    # Check for any captured commands
    if grep -E "echo|ls|pwd|whoami" "$ECAPTURE_LOG" >/dev/null 2>&1; then
        log_success "Found some captured commands in output"
        test_passed=1
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
run_zsh_test

exit $?
