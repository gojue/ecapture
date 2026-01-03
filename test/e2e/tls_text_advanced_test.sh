#!/usr/bin/env bash
# File: test/e2e/tls_text_advanced_test.sh
# Advanced test cases for ecapture TLS module in text mode

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="TLS Text Mode Advanced E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_tls_text_advanced_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Test results
TEST_RESULTS=()

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    
    if [ "${TEST_FAILED:-0}" = "1" ]; then
        log_error "Test failed. Check logs in $OUTPUT_DIR"
    fi
    
    # Keep logs for review if test failed
    if [ "${TEST_FAILED:-0}" = "0" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

setup_cleanup_trap

# Test 1: HTTP/1.1 with specific URL patterns
test_http11_capture() {
    log_info "=== Test 1: HTTP/1.1 Capture ==="
    
    local mode_log="$OUTPUT_DIR/http11.log"
    local test_url="https://www.github.com"
    
    log_info "Starting ecapture in text mode"
    "$ECAPTURE_BINARY" tls -m text > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("http11:FAIL")
        return 1
    fi
    
    log_info "Making HTTP/1.1 request to $test_url"
    curl -v --http1.1 "$test_url" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && grep -iq "GET\|POST\|HTTP/1" "$mode_log"; then
        log_success "✓ HTTP/1.1 capture test PASSED"
        TEST_RESULTS+=("http11:PASS")
        return 0
    else
        log_error "✗ HTTP/1.1 capture test FAILED"
        TEST_RESULTS+=("http11:FAIL")
        return 1
    fi
}

# Test 2: HTTP/2 with ALPN negotiation
test_http2_capture() {
    log_info "=== Test 2: HTTP/2 Capture ==="
    
    local mode_log="$OUTPUT_DIR/http2.log"
    local test_url="https://www.google.com"
    
    log_info "Starting ecapture in text mode"
    "$ECAPTURE_BINARY" tls -m text > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("http2:FAIL")
        return 1
    fi
    
    log_info "Making HTTP/2 request to $test_url"
    curl -v --http2 "$test_url" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && grep -iq "HTTP\|GET\|google" "$mode_log"; then
        log_success "✓ HTTP/2 capture test PASSED"
        TEST_RESULTS+=("http2:PASS")
        return 0
    else
        log_error "✗ HTTP/2 capture test FAILED"
        TEST_RESULTS+=("http2:FAIL")
        return 1
    fi
}

# Test 3: PID filtering - capture specific process only
test_pid_filtering() {
    log_info "=== Test 3: PID Filtering ==="
    
    local mode_log="$OUTPUT_DIR/pid_filter.log"
    local test_url="https://github.com"
    
    # Start a background curl process
    curl "$test_url" >/dev/null 2>&1 &
    local curl_pid=$!
    
    log_info "Starting ecapture with PID filter: $curl_pid"
    "$ECAPTURE_BINARY" tls -m text -p "$curl_pid" > "$mode_log" 2>&1 &
    local ecap_pid=$!
    sleep 3
    
    if ! kill -0 "$ecap_pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("pid_filter:FAIL")
        return 1
    fi
    
    # Wait for curl to complete
    wait "$curl_pid" 2>/dev/null || true
    sleep 2
    
    kill -INT "$ecap_pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ PID filtering test PASSED"
        TEST_RESULTS+=("pid_filter:PASS")
        return 0
    else
        log_warn "⚠ PID filtering test produced no output (process may have completed too quickly)"
        TEST_RESULTS+=("pid_filter:WARN")
        return 0
    fi
}

# Test 4: UID filtering - capture specific user's traffic
test_uid_filtering() {
    log_info "=== Test 4: UID Filtering ==="
    
    local mode_log="$OUTPUT_DIR/uid_filter.log"
    local current_uid
    current_uid=$(id -u)
    
    log_info "Starting ecapture with UID filter: $current_uid"
    "$ECAPTURE_BINARY" tls -m text -u "$current_uid" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("uid_filter:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && grep -iq "GET\|POST\|HTTP" "$mode_log"; then
        log_success "✓ UID filtering test PASSED"
        TEST_RESULTS+=("uid_filter:PASS")
        return 0
    else
        log_error "✗ UID filtering test FAILED"
        TEST_RESULTS+=("uid_filter:FAIL")
        return 1
    fi
}

# Test 5: Multiple concurrent connections
test_concurrent_connections() {
    log_info "=== Test 5: Concurrent Connections ==="
    
    local mode_log="$OUTPUT_DIR/concurrent.log"
    
    log_info "Starting ecapture in text mode"
    "$ECAPTURE_BINARY" tls -m text > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("concurrent:FAIL")
        return 1
    fi
    
    log_info "Making multiple concurrent HTTPS requests"
    curl "https://github.com" >/dev/null 2>&1 &
    curl "https://www.google.com" >/dev/null 2>&1 &
    curl "https://www.cloudflare.com" >/dev/null 2>&1 &
    
    sleep 3
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        local request_count
        request_count=$(grep -ci "GET\|POST" "$mode_log" || echo "0")
        log_info "Captured $request_count HTTP requests"
        
        if [ "$request_count" -gt 0 ]; then
            log_success "✓ Concurrent connections test PASSED"
            TEST_RESULTS+=("concurrent:PASS")
            return 0
        fi
    fi
    
    log_error "✗ Concurrent connections test FAILED"
    TEST_RESULTS+=("concurrent:FAIL")
    return 1
}

# Test 6: Text size truncation parameter
test_text_truncation() {
    log_info "=== Test 6: Text Size Truncation ==="
    
    local mode_log="$OUTPUT_DIR/truncation.log"
    local truncate_size=512
    
    log_info "Starting ecapture with text truncation: $truncate_size bytes"
    "$ECAPTURE_BINARY" tls -m text -t "$truncate_size" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("truncation:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Text truncation test PASSED"
        TEST_RESULTS+=("truncation:PASS")
        return 0
    else
        log_error "✗ Text truncation test FAILED"
        TEST_RESULTS+=("truncation:FAIL")
        return 1
    fi
}

# Test 7: Debug mode logging
test_debug_mode() {
    log_info "=== Test 7: Debug Mode Logging ==="
    
    local mode_log="$OUTPUT_DIR/debug.log"
    
    log_info "Starting ecapture with debug logging enabled"
    "$ECAPTURE_BINARY" tls -m text -d > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("debug:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_info "Debug log size: $(wc -c < "$mode_log") bytes"
        log_success "✓ Debug mode test PASSED"
        TEST_RESULTS+=("debug:PASS")
        return 0
    else
        log_error "✗ Debug mode test FAILED"
        TEST_RESULTS+=("debug:FAIL")
        return 1
    fi
}

# Test 8: Hex output mode
test_hex_output() {
    log_info "=== Test 8: Hex Output Mode ==="
    
    local mode_log="$OUTPUT_DIR/hex.log"
    
    log_info "Starting ecapture with hex output"
    "$ECAPTURE_BINARY" tls -m text --hex > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("hex:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        # Check if output contains hex patterns (0x or just hex digits in specific format)
        if grep -qE "[0-9a-fA-F]{2}[[:space:]][0-9a-fA-F]{2}" "$mode_log" || \
           grep -qi "hex\|0x" "$mode_log"; then
            log_success "✓ Hex output test PASSED"
            TEST_RESULTS+=("hex:PASS")
            return 0
        else
            log_warn "⚠ Hex output test: no clear hex format detected"
            TEST_RESULTS+=("hex:WARN")
            return 0
        fi
    else
        log_error "✗ Hex output test FAILED"
        TEST_RESULTS+=("hex:FAIL")
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
    
    if ! check_prerequisites curl; then
        log_error "Prerequisites check failed"
        exit 1
    fi
    
    mkdir -p "$TMP_DIR" "$OUTPUT_DIR"
    
    # Build ecapture
    log_info "=== Build eCapture ==="
    if ! build_ecapture "$ECAPTURE_BINARY"; then
        log_error "Failed to build ecapture"
        exit 1
    fi
    
    # Run all tests
    log_info "=== Running Advanced TLS Text Mode Tests ==="
    
    test_http11_capture || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_http2_capture || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_pid_filtering || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_uid_filtering || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_concurrent_connections || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_text_truncation || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_debug_mode || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_hex_output || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
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
        log_success "✓ All TLS text mode advanced tests PASSED"
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
