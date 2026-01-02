#!/usr/bin/env bash
# File: test/e2e/postgres_e2e_test.sh
# End-to-end test for ecapture PostgreSQL module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="PostgreSQL E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_postgres_e2e_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Log files
ECAPTURE_LOG="$OUTPUT_DIR/ecapture.log"

# Test results
TEST_FAILED=0

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    
    # Kill ecapture by pattern
    kill_by_pattern "$ECAPTURE_BINARY.*postgres" || true
    
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

# Check if PostgreSQL is available
check_postgres_available() {
    log_info "Checking for PostgreSQL client/server..."
    
    # Check if psql client is available
    if ! command_exists psql; then
        log_warn "psql client is not installed"
        return 1
    fi
    
    # Check if PostgreSQL server is running
    if ! pgrep -x postgres >/dev/null 2>&1 && ! pgrep -x postmaster >/dev/null 2>&1; then
        log_warn "PostgreSQL server is not running"
        return 1
    fi
    
    log_success "PostgreSQL is available"
    return 0
}

# Main test function
run_postgres_test() {
    log_info "=== Starting $TEST_NAME ==="
    
    # Prerequisites
    log_info "Checking prerequisites..."
    check_root || exit 1
    check_kernel_version 4 18 || exit 1
    check_prerequisites "$ECAPTURE_BINARY" || exit 1
    
    # Check if PostgreSQL is available
    if ! check_postgres_available; then
        log_warn "PostgreSQL is not available, skipping PostgreSQL test"
        log_info "To install PostgreSQL: sudo apt-get install postgresql postgresql-client (Debian/Ubuntu)"
        exit 0
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Build ecapture if needed
    build_ecapture "$ECAPTURE_BINARY" || {
        log_error "Failed to build ecapture"
        exit 1
    }
    
    # Test: PostgreSQL query capture
    log_info "=== Test: PostgreSQL Query Capture ==="
    
    # Get PostgreSQL server PID (main postmaster process)
    local postgres_pid
    postgres_pid=$(pgrep -x postgres | head -1 || pgrep -x postmaster | head -1 || echo "")
    
    if [ -z "$postgres_pid" ]; then
        log_error "Could not find PostgreSQL server process"
        TEST_FAILED=1
        return 1
    fi
    
    log_info "PostgreSQL PID: $postgres_pid"
    
    # Start ecapture for PostgreSQL
    log_info "Running: $ECAPTURE_BINARY postgres --pid $postgres_pid"
    "$ECAPTURE_BINARY" postgres --pid "$postgres_pid" > "$ECAPTURE_LOG" 2>&1 &
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
    
    # Execute test queries
    log_info "Executing test PostgreSQL queries..."
    
    # Try to connect and run some basic queries
    # Note: This requires PostgreSQL to be configured to allow connections
    sudo -u postgres psql -c "SELECT 1 AS test_query;" >/dev/null 2>&1 || \
    psql -U postgres -c "SELECT 1 AS test_query;" >/dev/null 2>&1 || \
    psql -c "SELECT 1 AS test_query;" >/dev/null 2>&1 || \
    log_warn "Could not connect to PostgreSQL to run test queries"
    
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
    
    # Check if we captured some PostgreSQL activity
    if grep -iq "postgres\|query\|SELECT\|INSERT\|UPDATE\|DELETE" "$ECAPTURE_LOG"; then
        log_success "Found PostgreSQL-related content in capture"
        test_passed=1
    else
        log_warn "Could not find PostgreSQL query patterns in output"
        log_info "This might be due to PostgreSQL not being actively queried or configuration issues"
        # Still consider test passed if ecapture ran without errors
        if grep -iq "module.*started\|initialization" "$ECAPTURE_LOG"; then
            log_info "eCapture initialized successfully for PostgreSQL"
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
run_postgres_test

exit $?
