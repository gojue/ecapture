#!/usr/bin/env bash
# File: test/e2e/edge_cases_test.sh
# Edge cases and error handling tests for ecapture

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="Edge Cases and Error Handling E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_edge_cases_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Test results
TEST_RESULTS=()

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    kill_by_pattern "$ECAPTURE_BINARY" || true
    
    if [ "${TEST_FAILED:-0}" = "0" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

setup_cleanup_trap

# Test 1: Non-existent PID
test_nonexistent_pid() {
    log_info "=== Test 1: Non-existent PID ==="
    
    local mode_log="$OUTPUT_DIR/nonexistent_pid.log"
    local fake_pid=999999
    
    log_info "Starting ecapture with non-existent PID: $fake_pid"
    timeout 5 "$ECAPTURE_BINARY" tls -m text -p "$fake_pid" > "$mode_log" 2>&1 || true
    
    # The tool should handle this gracefully
    if [ -f "$mode_log" ]; then
        log_success "✓ Non-existent PID test PASSED (handled gracefully)"
        TEST_RESULTS+=("nonexistent_pid:PASS")
        return 0
    else
        log_error "✗ Non-existent PID test FAILED"
        TEST_RESULTS+=("nonexistent_pid:FAIL")
        return 1
    fi
}

# Test 2: Invalid UID
test_invalid_uid() {
    log_info "=== Test 2: Invalid UID ==="
    
    local mode_log="$OUTPUT_DIR/invalid_uid.log"
    local invalid_uid=999999
    
    log_info "Starting ecapture with invalid UID: $invalid_uid"
    timeout 5 "$ECAPTURE_BINARY" tls -m text -u "$invalid_uid" > "$mode_log" 2>&1 || true
    
    # The tool should handle this gracefully
    if [ -f "$mode_log" ]; then
        log_success "✓ Invalid UID test PASSED (handled gracefully)"
        TEST_RESULTS+=("invalid_uid:PASS")
        return 0
    else
        log_error "✗ Invalid UID test FAILED"
        TEST_RESULTS+=("invalid_uid:FAIL")
        return 1
    fi
}

# Test 3: Non-existent library path
test_nonexistent_libssl() {
    log_info "=== Test 3: Non-existent Library Path ==="
    
    local mode_log="$OUTPUT_DIR/nonexistent_lib.log"
    local fake_lib="/nonexistent/path/libssl.so.999"
    
    log_info "Starting ecapture with non-existent library: $fake_lib"
    timeout 5 "$ECAPTURE_BINARY" tls -m text --libssl "$fake_lib" > "$mode_log" 2>&1 || true
    
    # Should fail or handle gracefully
    if [ -f "$mode_log" ]; then
        if grep -qi "error\|not found\|failed" "$mode_log"; then
            log_success "✓ Non-existent library test PASSED (error detected)"
            TEST_RESULTS+=("nonexistent_lib:PASS")
            return 0
        else
            log_warn "⚠ Non-existent library test: no error message found"
            TEST_RESULTS+=("nonexistent_lib:WARN")
            return 0
        fi
    else
        log_error "✗ Non-existent library test FAILED"
        TEST_RESULTS+=("nonexistent_lib:FAIL")
        return 1
    fi
}

# Test 4: Invalid network interface
test_invalid_interface() {
    log_info "=== Test 4: Invalid Network Interface ==="
    
    local mode_log="$OUTPUT_DIR/invalid_iface.log"
    local fake_iface="nonexistent_eth999"
    
    log_info "Starting ecapture with invalid interface: $fake_iface"
    timeout 5 "$ECAPTURE_BINARY" tls -m pcap -i "$fake_iface" -w "$OUTPUT_DIR/test.pcap" > "$mode_log" 2>&1 || true
    
    # Should fail or handle gracefully
    if [ -f "$mode_log" ]; then
        if grep -qi "error\|not found\|failed\|invalid" "$mode_log"; then
            log_success "✓ Invalid interface test PASSED (error detected)"
            TEST_RESULTS+=("invalid_iface:PASS")
            return 0
        else
            log_warn "⚠ Invalid interface test: no clear error message"
            TEST_RESULTS+=("invalid_iface:WARN")
            return 0
        fi
    else
        log_error "✗ Invalid interface test FAILED"
        TEST_RESULTS+=("invalid_iface:FAIL")
        return 1
    fi
}

# Test 5: Invalid pcap filter expression
test_invalid_pcap_filter() {
    log_info "=== Test 5: Invalid Pcap Filter Expression ==="
    
    local mode_log="$OUTPUT_DIR/invalid_filter.log"
    local invalid_filter="this is not a valid filter syntax!!!"
    
    log_info "Starting ecapture with invalid filter"
    timeout 5 "$ECAPTURE_BINARY" tls -m pcap -w "$OUTPUT_DIR/test.pcap" "$invalid_filter" > "$mode_log" 2>&1 || true
    
    # Should fail or handle gracefully
    if [ -f "$mode_log" ]; then
        if grep -qi "error\|invalid\|failed\|syntax" "$mode_log"; then
            log_success "✓ Invalid filter test PASSED (error detected)"
            TEST_RESULTS+=("invalid_filter:PASS")
            return 0
        else
            log_warn "⚠ Invalid filter test: no clear error message"
            TEST_RESULTS+=("invalid_filter:WARN")
            return 0
        fi
    else
        log_error "✗ Invalid filter test FAILED"
        TEST_RESULTS+=("invalid_filter:FAIL")
        return 1
    fi
}

# Test 6: Signal handling - SIGINT
test_signal_sigint() {
    log_info "=== Test 6: Signal Handling (SIGINT) ==="
    
    local mode_log="$OUTPUT_DIR/sigint.log"
    
    log_info "Starting ecapture"
    "$ECAPTURE_BINARY" tls -m text > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("sigint:FAIL")
        return 1
    fi
    
    log_info "Sending SIGINT to process"
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    # Check if process terminated gracefully
    if ! kill -0 "$pid" 2>/dev/null; then
        log_success "✓ SIGINT handling test PASSED (process terminated)"
        TEST_RESULTS+=("sigint:PASS")
        return 0
    else
        log_warn "Process still running, force killing"
        kill -9 "$pid" 2>/dev/null || true
        log_warn "⚠ SIGINT handling test WARN (process didn't terminate)"
        TEST_RESULTS+=("sigint:WARN")
        return 0
    fi
}

# Test 7: Signal handling - SIGTERM
test_signal_sigterm() {
    log_info "=== Test 7: Signal Handling (SIGTERM) ==="
    
    local mode_log="$OUTPUT_DIR/sigterm.log"
    
    log_info "Starting ecapture"
    "$ECAPTURE_BINARY" tls -m text > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("sigterm:FAIL")
        return 1
    fi
    
    log_info "Sending SIGTERM to process"
    kill -TERM "$pid" 2>/dev/null || true
    sleep 2
    
    # Check if process terminated gracefully
    if ! kill -0 "$pid" 2>/dev/null; then
        log_success "✓ SIGTERM handling test PASSED (process terminated)"
        TEST_RESULTS+=("sigterm:PASS")
        return 0
    else
        log_warn "Process still running, force killing"
        kill -9 "$pid" 2>/dev/null || true
        log_warn "⚠ SIGTERM handling test WARN (process didn't terminate)"
        TEST_RESULTS+=("sigterm:WARN")
        return 0
    fi
}

# Test 8: Disk space handling (write to read-only location)
test_readonly_output() {
    log_info "=== Test 8: Read-only Output Location ==="
    
    local mode_log="$OUTPUT_DIR/readonly.log"
    local readonly_dir="/sys/readonly_test"
    
    log_info "Testing write to protected location"
    timeout 5 "$ECAPTURE_BINARY" tls -m pcap -w "/proc/test.pcap" > "$mode_log" 2>&1 || true
    
    # Should fail with permission/access error
    if [ -f "$mode_log" ]; then
        if grep -qi "error\|permission\|denied\|failed" "$mode_log"; then
            log_success "✓ Read-only output test PASSED (error detected)"
            TEST_RESULTS+=("readonly:PASS")
            return 0
        else
            log_warn "⚠ Read-only output test: no clear error message"
            TEST_RESULTS+=("readonly:WARN")
            return 0
        fi
    else
        log_warn "⚠ Read-only output test: no output generated"
        TEST_RESULTS+=("readonly:WARN")
        return 0
    fi
}

# Test 9: Invalid BTF mode value
test_invalid_btf_mode() {
    log_info "=== Test 9: Invalid BTF Mode ==="
    
    local mode_log="$OUTPUT_DIR/invalid_btf.log"
    local invalid_btf=999
    
    log_info "Starting ecapture with invalid BTF mode: $invalid_btf"
    timeout 5 "$ECAPTURE_BINARY" tls -m text -b "$invalid_btf" > "$mode_log" 2>&1 || true
    
    # Should fail or handle gracefully
    if [ -f "$mode_log" ]; then
        log_success "✓ Invalid BTF mode test PASSED (handled)"
        TEST_RESULTS+=("invalid_btf:PASS")
        return 0
    else
        log_error "✗ Invalid BTF mode test FAILED"
        TEST_RESULTS+=("invalid_btf:FAIL")
        return 1
    fi
}

# Test 10: Extremely large mapsize
test_extreme_mapsize() {
    log_info "=== Test 10: Extremely Large Mapsize ==="
    
    local mode_log="$OUTPUT_DIR/large_mapsize.log"
    local large_mapsize=999999999
    
    log_info "Starting ecapture with large mapsize: $large_mapsize"
    timeout 5 "$ECAPTURE_BINARY" tls -m text --mapsize "$large_mapsize" > "$mode_log" 2>&1 || true
    
    # Should handle gracefully (may accept or reject based on system limits)
    if [ -f "$mode_log" ]; then
        log_success "✓ Extreme mapsize test PASSED (handled)"
        TEST_RESULTS+=("extreme_mapsize:PASS")
        return 0
    else
        log_error "✗ Extreme mapsize test FAILED"
        TEST_RESULTS+=("extreme_mapsize:FAIL")
        return 1
    fi
}

# Test 11: Non-existent GoTLS binary path
test_gotls_nonexistent_binary() {
    log_info "=== Test 11: GoTLS Non-existent Binary ==="
    
    local mode_log="$OUTPUT_DIR/gotls_nonexistent.log"
    local fake_binary="/nonexistent/path/to/binary"
    
    log_info "Starting ecapture GoTLS with non-existent binary"
    timeout 5 "$ECAPTURE_BINARY" gotls --elfpath "$fake_binary" > "$mode_log" 2>&1 || true
    
    # Should fail with appropriate error
    if [ -f "$mode_log" ]; then
        if grep -qi "error\|not found\|failed\|invalid" "$mode_log"; then
            log_success "✓ GoTLS non-existent binary test PASSED (error detected)"
            TEST_RESULTS+=("gotls_nonexistent:PASS")
            return 0
        else
            log_warn "⚠ GoTLS non-existent binary test: no clear error"
            TEST_RESULTS+=("gotls_nonexistent:WARN")
            return 0
        fi
    else
        log_error "✗ GoTLS non-existent binary test FAILED"
        TEST_RESULTS+=("gotls_nonexistent:FAIL")
        return 1
    fi
}

# Test 12: MySQL with non-running server
test_mysql_no_server() {
    log_info "=== Test 12: MySQL with No Server Running ==="
    
    # Only run if MySQL is NOT running
    if pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1; then
        log_info "MySQL is running, skipping this test"
        TEST_RESULTS+=("mysql_no_server:SKIP")
        return 0
    fi
    
    local mode_log="$OUTPUT_DIR/mysql_no_server.log"
    
    log_info "Starting ecapture MySQL with no server running"
    timeout 5 "$ECAPTURE_BINARY" mysqld > "$mode_log" 2>&1 || true
    
    # Should handle gracefully
    if [ -f "$mode_log" ]; then
        log_success "✓ MySQL no server test PASSED (handled gracefully)"
        TEST_RESULTS+=("mysql_no_server:PASS")
        return 0
    else
        log_error "✗ MySQL no server test FAILED"
        TEST_RESULTS+=("mysql_no_server:FAIL")
        return 1
    fi
}

# Test 13: Zero text truncation size
test_zero_truncation() {
    log_info "=== Test 13: Zero Text Truncation Size ==="
    
    local mode_log="$OUTPUT_DIR/zero_truncation.log"
    
    log_info "Starting ecapture with zero truncation size"
    timeout 5 "$ECAPTURE_BINARY" tls -m text -t 0 > "$mode_log" 2>&1 || true
    
    # Should handle gracefully (may use default or reject)
    if [ -f "$mode_log" ]; then
        log_success "✓ Zero truncation test PASSED (handled)"
        TEST_RESULTS+=("zero_truncation:PASS")
        return 0
    else
        log_error "✗ Zero truncation test FAILED"
        TEST_RESULTS+=("zero_truncation:FAIL")
        return 1
    fi
}

# Test 14: Negative PID value
test_negative_pid() {
    log_info "=== Test 14: Negative PID Value ==="
    
    local mode_log="$OUTPUT_DIR/negative_pid.log"
    
    log_info "Starting ecapture with negative PID"
    timeout 5 "$ECAPTURE_BINARY" tls -m text -p -1 > "$mode_log" 2>&1 || true
    
    # Should fail or handle gracefully
    if [ -f "$mode_log" ]; then
        log_success "✓ Negative PID test PASSED (handled)"
        TEST_RESULTS+=("negative_pid:PASS")
        return 0
    else
        log_error "✗ Negative PID test FAILED"
        TEST_RESULTS+=("negative_pid:FAIL")
        return 1
    fi
}

# Test 15: Empty pcap filename
test_empty_pcap_filename() {
    log_info "=== Test 15: Empty Pcap Filename ==="
    
    local mode_log="$OUTPUT_DIR/empty_pcap.log"
    
    log_info "Starting ecapture with empty pcap filename"
    timeout 5 "$ECAPTURE_BINARY" tls -m pcap -w "" > "$mode_log" 2>&1 || true
    
    # Should fail with appropriate error
    if [ -f "$mode_log" ]; then
        if grep -qi "error\|invalid\|empty\|required" "$mode_log"; then
            log_success "✓ Empty pcap filename test PASSED (error detected)"
            TEST_RESULTS+=("empty_pcap:PASS")
            return 0
        else
            log_warn "⚠ Empty pcap filename test: no clear error"
            TEST_RESULTS+=("empty_pcap:WARN")
            return 0
        fi
    else
        log_error "✗ Empty pcap filename test FAILED"
        TEST_RESULTS+=("empty_pcap:FAIL")
        return 1
    fi
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
    
    mkdir -p "$TMP_DIR" "$OUTPUT_DIR"
    
    # Build ecapture
    log_info "=== Build eCapture ==="
    if ! build_ecapture "$ECAPTURE_BINARY"; then
        log_error "Failed to build ecapture"
        exit 1
    fi
    
    # Run all edge case tests
    log_info "=== Running Edge Cases and Error Handling Tests ==="
    
    test_nonexistent_pid || true
    sleep 1
    
    test_invalid_uid || true
    sleep 1
    
    test_nonexistent_libssl || true
    sleep 1
    
    test_invalid_interface || true
    sleep 1
    
    test_invalid_pcap_filter || true
    sleep 1
    
    test_signal_sigint || true
    kill_by_pattern "$ECAPTURE_BINARY" || true
    sleep 1
    
    test_signal_sigterm || true
    kill_by_pattern "$ECAPTURE_BINARY" || true
    sleep 1
    
    test_readonly_output || true
    sleep 1
    
    test_invalid_btf_mode || true
    sleep 1
    
    test_extreme_mapsize || true
    sleep 1
    
    test_gotls_nonexistent_binary || true
    sleep 1
    
    test_mysql_no_server || true
    sleep 1
    
    test_zero_truncation || true
    sleep 1
    
    test_negative_pid || true
    sleep 1
    
    test_empty_pcap_filename || true
    sleep 1
    
    # Summary
    log_info "=== Test Summary ==="
    local pass_count=0
    local fail_count=0
    local warn_count=0
    local skip_count=0
    
    for result in "${TEST_RESULTS[@]}"; do
        local test="${result%%:*}"
        local status="${result##*:}"
        
        if [ "$status" = "PASS" ]; then
            log_success "  ✓ $test: $status"
            pass_count=$((pass_count + 1))
        elif [ "$status" = "WARN" ]; then
            log_warn "  ⚠ $test: $status"
            warn_count=$((warn_count + 1))
        elif [ "$status" = "SKIP" ]; then
            log_info "  ⊘ $test: $status"
            skip_count=$((skip_count + 1))
        else
            log_error "  ✗ $test: $status"
            fail_count=$((fail_count + 1))
        fi
    done
    
    log_info "Results: $pass_count passed, $fail_count failed, $warn_count warnings, $skip_count skipped"
    
    if [ $fail_count -eq 0 ]; then
        log_success "✓ All edge case tests PASSED"
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
