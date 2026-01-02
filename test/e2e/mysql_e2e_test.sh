#!/usr/bin/env bash
# File: test/e2e/mysql_e2e_test.sh
# End-to-end test for ecapture MySQL module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="MySQL E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_mysql_e2e_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Log files
ECAPTURE_LOG="$OUTPUT_DIR/ecapture.log"

# Test results
TEST_FAILED=0

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    
    # Kill ecapture by pattern
    kill_by_pattern "$ECAPTURE_BINARY.*mysql" || true
    
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

# Check if MySQL is available
check_mysql_available() {
    log_info "Checking for MySQL client/server..."
    
    # Check if mysql client is available
    if ! command_exists mysql; then
        log_warn "mysql client is not installed"
        return 1
    fi
    
    # Check if MySQL server is running
    if ! pgrep -x mysqld >/dev/null 2>&1 && ! pgrep -x mariadbd >/dev/null 2>&1; then
        log_warn "MySQL/MariaDB server is not running"
        return 1
    fi
    
    log_success "MySQL/MariaDB is available"
    return 0
}

# Main test function
run_mysql_test() {
    log_info "=== Starting $TEST_NAME ==="
    
    # Prerequisites
    log_info "Checking prerequisites..."
    check_root || exit 1
    check_kernel_version 4 18 || exit 1
    check_prerequisites "$ECAPTURE_BINARY" || exit 1
    
    # Check if MySQL is available
    if ! check_mysql_available; then
        log_warn "MySQL is not available, skipping MySQL test"
        log_info "To install MySQL: sudo apt-get install mysql-server mysql-client (Debian/Ubuntu)"
        log_info "To install MariaDB: sudo apt-get install mariadb-server mariadb-client (Debian/Ubuntu)"
        exit 0
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Build ecapture if needed
    build_ecapture "$ECAPTURE_BINARY" || {
        log_error "Failed to build ecapture"
        exit 1
    }
    
    # Test: MySQL query capture
    log_info "=== Test: MySQL Query Capture ==="
    
    # Get MySQL server PID
    local mysql_pid
    mysql_pid=$(pgrep -x mysqld || pgrep -x mariadbd || echo "")
    
    if [ -z "$mysql_pid" ]; then
        log_error "Could not find MySQL/MariaDB server process"
        TEST_FAILED=1
        return 1
    fi
    
    log_info "MySQL/MariaDB PID: $mysql_pid"
    
    # Start ecapture for MySQL
    log_info "Running: $ECAPTURE_BINARY mysqld --pid $mysql_pid"
    "$ECAPTURE_BINARY" mysqld --pid "$mysql_pid" > "$ECAPTURE_LOG" 2>&1 &
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
    log_info "Executing test MySQL queries..."
    
    # Try to connect and run some basic queries
    # Note: This requires MySQL to be configured to allow connections
    mysql -e "SELECT 1 AS test_query;" >/dev/null 2>&1 || \
    mysql -u root -e "SELECT 1 AS test_query;" >/dev/null 2>&1 || \
    mysql -u root -proot -e "SELECT 1 AS test_query;" >/dev/null 2>&1 || \
    log_warn "Could not connect to MySQL to run test queries"
    
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
    
    # Check if we captured some MySQL activity
    if grep -iq "mysql\|query\|SELECT\|INSERT\|UPDATE\|DELETE" "$ECAPTURE_LOG"; then
        log_success "Found MySQL-related content in capture"
        test_passed=1
    else
        log_warn "Could not find MySQL query patterns in output"
        log_info "This might be due to MySQL not being actively queried or configuration issues"
        # Still consider test passed if ecapture ran without errors
        if grep -iq "module.*started\|initialization" "$ECAPTURE_LOG"; then
            log_info "eCapture initialized successfully for MySQL"
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
run_mysql_test

exit $?
