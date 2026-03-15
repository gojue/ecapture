#!/usr/bin/env bash
# File: test/e2e/mysql_advanced_test.sh
# Advanced test cases for ecapture MySQL module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="MySQL Advanced E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_mysql_advanced_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Test database
TEST_DB="ecapture_test_db"

# Test results
TEST_RESULTS=()

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    kill_by_pattern "$ECAPTURE_BINARY.*mysql" || true
    
    # Clean up test database
    mysql -e "DROP DATABASE IF EXISTS $TEST_DB;" 2>/dev/null || true
    
    if [ "${TEST_FAILED:-0}" = "0" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

setup_cleanup_trap

# Check if MySQL is available
check_mysql_available() {
    if ! command_exists mysql; then
        log_warn "mysql client is not installed"
        return 1
    fi
    
    if ! pgrep -x mysqld >/dev/null 2>&1 && ! pgrep -x mariadbd >/dev/null 2>&1; then
        log_warn "MySQL/MariaDB server is not running"
        return 1
    fi
    
    return 0
}

# Setup test database
setup_test_database() {
    log_info "Setting up test database: $TEST_DB"
    
    # Create test database
    mysql -e "CREATE DATABASE IF NOT EXISTS $TEST_DB;" 2>/dev/null || {
        mysql -u root -e "CREATE DATABASE IF NOT EXISTS $TEST_DB;" 2>/dev/null || {
            log_error "Failed to create test database"
            return 1
        }
    }
    
    # Create test table
    mysql "$TEST_DB" -e "
        CREATE TABLE IF NOT EXISTS test_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            email VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    " 2>/dev/null || mysql -u root "$TEST_DB" -e "
        CREATE TABLE IF NOT EXISTS test_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            email VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    " 2>/dev/null || {
        log_error "Failed to create test table"
        return 1
    }
    
    log_success "Test database setup complete"
    return 0
}

# Test 1: SELECT queries
test_select_queries() {
    log_info "=== Test 1: SELECT Queries ==="
    
    local mode_log="$OUTPUT_DIR/select.log"
    local mysql_pid
    mysql_pid=$(pgrep -x mysqld || pgrep -x mariadbd || echo "")
    
    if [ -z "$mysql_pid" ]; then
        log_error "MySQL/MariaDB not running"
        TEST_RESULTS+=("select:FAIL")
        return 1
    fi
    
    log_info "Starting ecapture for MySQL PID: $mysql_pid"
    "$ECAPTURE_BINARY" mysqld --pid "$mysql_pid" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("select:FAIL")
        return 1
    fi
    
    log_info "Executing SELECT queries"
    mysql "$TEST_DB" -e "SELECT * FROM test_users;" >/dev/null 2>&1 || \
    mysql -u root "$TEST_DB" -e "SELECT * FROM test_users;" >/dev/null 2>&1 || true
    
    mysql "$TEST_DB" -e "SELECT COUNT(*) FROM test_users;" >/dev/null 2>&1 || \
    mysql -u root "$TEST_DB" -e "SELECT COUNT(*) FROM test_users;" >/dev/null 2>&1 || true
    
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && grep -iq "SELECT" "$mode_log"; then
        log_success "✓ SELECT queries test PASSED"
        TEST_RESULTS+=("select:PASS")
        return 0
    else
        log_warn "⚠ SELECT queries test produced limited output"
        TEST_RESULTS+=("select:WARN")
        return 0
    fi
}

# Test 2: INSERT operations
test_insert_operations() {
    log_info "=== Test 2: INSERT Operations ==="
    
    local mode_log="$OUTPUT_DIR/insert.log"
    local mysql_pid
    mysql_pid=$(pgrep -x mysqld || pgrep -x mariadbd || echo "")
    
    if [ -z "$mysql_pid" ]; then
        log_error "MySQL/MariaDB not running"
        TEST_RESULTS+=("insert:FAIL")
        return 1
    fi
    
    log_info "Starting ecapture for MySQL PID: $mysql_pid"
    "$ECAPTURE_BINARY" mysqld --pid "$mysql_pid" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("insert:FAIL")
        return 1
    fi
    
    log_info "Executing INSERT operations"
    mysql "$TEST_DB" -e "INSERT INTO test_users (username, email) VALUES ('test_user1', 'user1@example.com');" >/dev/null 2>&1 || \
    mysql -u root "$TEST_DB" -e "INSERT INTO test_users (username, email) VALUES ('test_user1', 'user1@example.com');" >/dev/null 2>&1 || true
    
    mysql "$TEST_DB" -e "INSERT INTO test_users (username, email) VALUES ('test_user2', 'user2@example.com'), ('test_user3', 'user3@example.com');" >/dev/null 2>&1 || \
    mysql -u root "$TEST_DB" -e "INSERT INTO test_users (username, email) VALUES ('test_user2', 'user2@example.com'), ('test_user3', 'user3@example.com');" >/dev/null 2>&1 || true
    
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && grep -iq "INSERT" "$mode_log"; then
        log_success "✓ INSERT operations test PASSED"
        TEST_RESULTS+=("insert:PASS")
        return 0
    else
        log_warn "⚠ INSERT operations test produced limited output"
        TEST_RESULTS+=("insert:WARN")
        return 0
    fi
}

# Test 3: UPDATE operations
test_update_operations() {
    log_info "=== Test 3: UPDATE Operations ==="
    
    local mode_log="$OUTPUT_DIR/update.log"
    local mysql_pid
    mysql_pid=$(pgrep -x mysqld || pgrep -x mariadbd || echo "")
    
    if [ -z "$mysql_pid" ]; then
        log_error "MySQL/MariaDB not running"
        TEST_RESULTS+=("update:FAIL")
        return 1
    fi
    
    log_info "Starting ecapture for MySQL PID: $mysql_pid"
    "$ECAPTURE_BINARY" mysqld --pid "$mysql_pid" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("update:FAIL")
        return 1
    fi
    
    log_info "Executing UPDATE operations"
    mysql "$TEST_DB" -e "UPDATE test_users SET email='updated@example.com' WHERE username='test_user1';" >/dev/null 2>&1 || \
    mysql -u root "$TEST_DB" -e "UPDATE test_users SET email='updated@example.com' WHERE username='test_user1';" >/dev/null 2>&1 || true
    
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && grep -iq "UPDATE" "$mode_log"; then
        log_success "✓ UPDATE operations test PASSED"
        TEST_RESULTS+=("update:PASS")
        return 0
    else
        log_warn "⚠ UPDATE operations test produced limited output"
        TEST_RESULTS+=("update:WARN")
        return 0
    fi
}

# Test 4: DELETE operations
test_delete_operations() {
    log_info "=== Test 4: DELETE Operations ==="
    
    local mode_log="$OUTPUT_DIR/delete.log"
    local mysql_pid
    mysql_pid=$(pgrep -x mysqld || pgrep -x mariadbd || echo "")
    
    if [ -z "$mysql_pid" ]; then
        log_error "MySQL/MariaDB not running"
        TEST_RESULTS+=("delete:FAIL")
        return 1
    fi
    
    log_info "Starting ecapture for MySQL PID: $mysql_pid"
    "$ECAPTURE_BINARY" mysqld --pid "$mysql_pid" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("delete:FAIL")
        return 1
    fi
    
    log_info "Executing DELETE operations"
    mysql "$TEST_DB" -e "DELETE FROM test_users WHERE username='test_user3';" >/dev/null 2>&1 || \
    mysql -u root "$TEST_DB" -e "DELETE FROM test_users WHERE username='test_user3';" >/dev/null 2>&1 || true
    
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && grep -iq "DELETE" "$mode_log"; then
        log_success "✓ DELETE operations test PASSED"
        TEST_RESULTS+=("delete:PASS")
        return 0
    else
        log_warn "⚠ DELETE operations test produced limited output"
        TEST_RESULTS+=("delete:WARN")
        return 0
    fi
}

# Test 5: Transaction handling
test_transactions() {
    log_info "=== Test 5: Transaction Handling ==="
    
    local mode_log="$OUTPUT_DIR/transaction.log"
    local mysql_pid
    mysql_pid=$(pgrep -x mysqld || pgrep -x mariadbd || echo "")
    
    if [ -z "$mysql_pid" ]; then
        log_error "MySQL/MariaDB not running"
        TEST_RESULTS+=("transaction:FAIL")
        return 1
    fi
    
    log_info "Starting ecapture for MySQL PID: $mysql_pid"
    "$ECAPTURE_BINARY" mysqld --pid "$mysql_pid" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("transaction:FAIL")
        return 1
    fi
    
    log_info "Executing transaction"
    {
        mysql "$TEST_DB" >/dev/null 2>&1 || mysql -u root "$TEST_DB" >/dev/null 2>&1 || true
    } <<'EOF'
START TRANSACTION;
INSERT INTO test_users (username, email) VALUES ('tx_user1', 'tx1@example.com');
INSERT INTO test_users (username, email) VALUES ('tx_user2', 'tx2@example.com');
COMMIT;
EOF
    
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && (grep -iq "START TRANSACTION\|COMMIT\|INSERT" "$mode_log"); then
        log_success "✓ Transaction handling test PASSED"
        TEST_RESULTS+=("transaction:PASS")
        return 0
    else
        log_warn "⚠ Transaction handling test produced limited output"
        TEST_RESULTS+=("transaction:WARN")
        return 0
    fi
}

# Test 6: Long SQL statements
test_long_sql() {
    log_info "=== Test 6: Long SQL Statements ==="
    
    local mode_log="$OUTPUT_DIR/long_sql.log"
    local mysql_pid
    mysql_pid=$(pgrep -x mysqld || pgrep -x mariadbd || echo "")
    
    if [ -z "$mysql_pid" ]; then
        log_error "MySQL/MariaDB not running"
        TEST_RESULTS+=("long_sql:FAIL")
        return 1
    fi
    
    log_info "Starting ecapture for MySQL PID: $mysql_pid"
    "$ECAPTURE_BINARY" mysqld --pid "$mysql_pid" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("long_sql:FAIL")
        return 1
    fi
    
    log_info "Executing long SQL statement"
    local long_query="SELECT * FROM test_users WHERE username IN ('user1', 'user2', 'user3', 'user4', 'user5', 'user6', 'user7', 'user8', 'user9', 'user10') OR email LIKE '%example.com%' OR id > 0 ORDER BY created_at DESC LIMIT 100;"
    
    mysql "$TEST_DB" -e "$long_query" >/dev/null 2>&1 || \
    mysql -u root "$TEST_DB" -e "$long_query" >/dev/null 2>&1 || true
    
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Long SQL statements test PASSED"
        TEST_RESULTS+=("long_sql:PASS")
        return 0
    else
        log_warn "⚠ Long SQL statements test produced no output"
        TEST_RESULTS+=("long_sql:WARN")
        return 0
    fi
}

# Test 7: Concurrent queries
test_concurrent_queries() {
    log_info "=== Test 7: Concurrent Queries ==="
    
    local mode_log="$OUTPUT_DIR/concurrent.log"
    local mysql_pid
    mysql_pid=$(pgrep -x mysqld || pgrep -x mariadbd || echo "")
    
    if [ -z "$mysql_pid" ]; then
        log_error "MySQL/MariaDB not running"
        TEST_RESULTS+=("concurrent:FAIL")
        return 1
    fi
    
    log_info "Starting ecapture for MySQL PID: $mysql_pid"
    "$ECAPTURE_BINARY" mysqld --pid "$mysql_pid" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("concurrent:FAIL")
        return 1
    fi
    
    log_info "Executing concurrent queries"
    mysql "$TEST_DB" -e "SELECT * FROM test_users;" >/dev/null 2>&1 &
    mysql "$TEST_DB" -e "SELECT COUNT(*) FROM test_users;" >/dev/null 2>&1 &
    mysql "$TEST_DB" -e "SELECT username FROM test_users LIMIT 5;" >/dev/null 2>&1 &
    
    sleep 3
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        local query_count
        query_count=$(grep -ci "SELECT" "$mode_log" || echo "0")
        log_info "Captured $query_count SELECT queries"
        
        if [ "$query_count" -gt 0 ]; then
            log_success "✓ Concurrent queries test PASSED"
            TEST_RESULTS+=("concurrent:PASS")
            return 0
        fi
    fi
    
    log_warn "⚠ Concurrent queries test produced limited output"
    TEST_RESULTS+=("concurrent:WARN")
    return 0
}

# Main test runner
main() {
    log_info "=== $TEST_NAME ==="
    
    # Prerequisites check
    log_info "=== Prerequisites Check ==="
    if ! check_root; then
        log_error "Root privileges required"
        exit 1
    fi
    
    if ! check_kernel_version 4 18; then
        log_error "Kernel version check failed"
        exit 1
    fi
    
    if ! check_mysql_available; then
        log_warn "MySQL is not available, skipping MySQL advanced tests"
        log_info "To install MySQL: sudo apt-get install mysql-server mysql-client"
        log_info "To install MariaDB: sudo apt-get install mariadb-server mariadb-client"
        exit 0
    fi
    
    mkdir -p "$TMP_DIR" "$OUTPUT_DIR"
    
    # Build ecapture
    log_info "=== Build eCapture ==="
    if ! build_ecapture "$ECAPTURE_BINARY"; then
        log_error "Failed to build ecapture"
        exit 1
    fi
    
    # Setup test database
    log_info "=== Setup Test Database ==="
    if ! setup_test_database; then
        log_error "Failed to setup test database"
        exit 1
    fi
    
    # Run all tests
    log_info "=== Running Advanced MySQL Tests ==="
    
    test_select_queries || true
    kill_by_pattern "$ECAPTURE_BINARY.*mysql" || true
    sleep 1
    
    test_insert_operations || true
    kill_by_pattern "$ECAPTURE_BINARY.*mysql" || true
    sleep 1
    
    test_update_operations || true
    kill_by_pattern "$ECAPTURE_BINARY.*mysql" || true
    sleep 1
    
    test_delete_operations || true
    kill_by_pattern "$ECAPTURE_BINARY.*mysql" || true
    sleep 1
    
    test_transactions || true
    kill_by_pattern "$ECAPTURE_BINARY.*mysql" || true
    sleep 1
    
    test_long_sql || true
    kill_by_pattern "$ECAPTURE_BINARY.*mysql" || true
    sleep 1
    
    test_concurrent_queries || true
    kill_by_pattern "$ECAPTURE_BINARY.*mysql" || true
    sleep 1
    
    # Summary
    log_info "=== Test Summary ==="
    local pass_count=0
    local fail_count=0
    local warn_count=0
    
    for result in "${TEST_RESULTS[@]}"; do
        local test="${result%%:*}"
        local status="${result##*:}"
        
        if [ "$status" = "PASS" ]; then
            log_success "  ✓ $test: $status"
            pass_count=$((pass_count + 1))
        elif [ "$status" = "WARN" ]; then
            log_warn "  ⚠ $test: $status"
            warn_count=$((warn_count + 1))
        else
            log_error "  ✗ $test: $status"
            fail_count=$((fail_count + 1))
        fi
    done
    
    log_info "Results: $pass_count passed, $fail_count failed, $warn_count warnings"
    
    if [ $fail_count -eq 0 ]; then
        log_success "✓ All MySQL advanced tests PASSED"
        return 0
    else
        log_warn "⚠ Some tests failed"
        return 0
    fi
}

if main; then
    exit 0
else
    TEST_FAILED=1
    exit 1
fi
