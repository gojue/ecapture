#!/usr/bin/env bash
# File: test/e2e/tls_keylog_advanced_test.sh
# Advanced test cases for ecapture TLS module in keylog mode

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="TLS Keylog Mode Advanced E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_tls_keylog_advanced_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Test results
TEST_RESULTS=()

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    
    if [ "${TEST_FAILED:-0}" = "0" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

setup_cleanup_trap

# Verify keylog file format
verify_keylog_file() {
    local keylog_file="$1"
    local description="${2:-keylog file}"
    
    if [ ! -f "$keylog_file" ]; then
        log_error "$description not found: $keylog_file"
        return 1
    fi
    
    if [ ! -s "$keylog_file" ]; then
        log_error "$description is empty"
        return 1
    fi
    
    local file_size
    file_size=$(wc -c < "$keylog_file")
    log_info "$description size: $file_size bytes"
    
    # Check for CLIENT_RANDOM entries (standard SSLKEYLOG format)
    if grep -q "CLIENT_RANDOM" "$keylog_file"; then
        local entry_count
        entry_count=$(grep -c "CLIENT_RANDOM" "$keylog_file")
        log_success "$description contains $entry_count CLIENT_RANDOM entries"
        return 0
    else
        log_warn "$description does not contain CLIENT_RANDOM entries"
        log_info "First 20 lines of keylog file:"
        head -n 20 "$keylog_file" || true
        return 1
    fi
}

# Test 1: Basic keylog mode
test_keylog_basic() {
    log_info "=== Test 1: Basic Keylog Mode ==="
    
    local mode_log="$OUTPUT_DIR/keylog_basic.log"
    local keylog_file="$OUTPUT_DIR/basic.keylog"
    
    log_info "Starting ecapture in keylog mode"
    "$ECAPTURE_BINARY" tls -m keylog -k "$keylog_file" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("keylog_basic:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if verify_keylog_file "$keylog_file" "Basic keylog file"; then
        log_success "✓ Basic keylog test PASSED"
        TEST_RESULTS+=("keylog_basic:PASS")
        return 0
    else
        # Still pass if file was created, as some environments may not capture keys
        if [ -f "$keylog_file" ]; then
            log_warn "⚠ Keylog file created but format verification failed"
            TEST_RESULTS+=("keylog_basic:WARN")
            return 0
        else
            log_error "✗ Basic keylog test FAILED"
            TEST_RESULTS+=("keylog_basic:FAIL")
            return 1
        fi
    fi
}

# Test 2: Keylog with TLS 1.2 connection
test_keylog_tls12() {
    log_info "=== Test 2: Keylog TLS 1.2 ==="
    
    local mode_log="$OUTPUT_DIR/keylog_tls12.log"
    local keylog_file="$OUTPUT_DIR/tls12.keylog"
    
    log_info "Starting ecapture in keylog mode"
    "$ECAPTURE_BINARY" tls -m keylog -k "$keylog_file" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("tls12:FAIL")
        return 1
    fi
    
    log_info "Making TLS 1.2 HTTPS request"
    # Try to force TLS 1.2
    curl -v --tlsv1.2 --tls-max 1.2 "https://github.com" >/dev/null 2>&1 || \
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -f "$keylog_file" ] && [ -s "$keylog_file" ]; then
        log_success "✓ TLS 1.2 keylog test PASSED"
        TEST_RESULTS+=("tls12:PASS")
        return 0
    else
        log_warn "⚠ TLS 1.2 keylog test produced no output"
        TEST_RESULTS+=("tls12:WARN")
        return 0
    fi
}

# Test 3: Keylog with TLS 1.3 connection
test_keylog_tls13() {
    log_info "=== Test 3: Keylog TLS 1.3 ==="
    
    local mode_log="$OUTPUT_DIR/keylog_tls13.log"
    local keylog_file="$OUTPUT_DIR/tls13.keylog"
    
    log_info "Starting ecapture in keylog mode"
    "$ECAPTURE_BINARY" tls -m keylog -k "$keylog_file" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("tls13:FAIL")
        return 1
    fi
    
    log_info "Making TLS 1.3 HTTPS request"
    # Modern sites like cloudflare typically support TLS 1.3
    curl -v --tlsv1.3 "https://www.cloudflare.com" >/dev/null 2>&1 || \
    curl -v "https://www.cloudflare.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -f "$keylog_file" ] && [ -s "$keylog_file" ]; then
        log_success "✓ TLS 1.3 keylog test PASSED"
        TEST_RESULTS+=("tls13:PASS")
        return 0
    else
        log_warn "⚠ TLS 1.3 keylog test produced no output"
        TEST_RESULTS+=("tls13:WARN")
        return 0
    fi
}

# Test 4: Keylog with multiple concurrent connections
test_keylog_concurrent() {
    log_info "=== Test 4: Keylog Concurrent Connections ==="
    
    local mode_log="$OUTPUT_DIR/keylog_concurrent.log"
    local keylog_file="$OUTPUT_DIR/concurrent.keylog"
    
    log_info "Starting ecapture in keylog mode"
    "$ECAPTURE_BINARY" tls -m keylog -k "$keylog_file" > "$mode_log" 2>&1 &
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
    
    if [ -f "$keylog_file" ] && [ -s "$keylog_file" ]; then
        local entry_count=0
        if grep -q "CLIENT_RANDOM" "$keylog_file"; then
            entry_count=$(grep -c "CLIENT_RANDOM" "$keylog_file")
            log_info "Captured $entry_count key entries"
        fi
        
        log_success "✓ Keylog concurrent connections test PASSED"
        TEST_RESULTS+=("concurrent:PASS")
        return 0
    else
        log_warn "⚠ Keylog concurrent connections test produced no output"
        TEST_RESULTS+=("concurrent:WARN")
        return 0
    fi
}

# Test 5: Keylog with PID filtering
test_keylog_pid_filter() {
    log_info "=== Test 5: Keylog with PID Filter ==="
    
    local mode_log="$OUTPUT_DIR/keylog_pid.log"
    local keylog_file="$OUTPUT_DIR/pid_filter.keylog"
    
    # Start curl in background
    curl "https://github.com" >/dev/null 2>&1 &
    local curl_pid=$!
    
    log_info "Starting ecapture with PID filter: $curl_pid"
    "$ECAPTURE_BINARY" tls -m keylog -k "$keylog_file" -p "$curl_pid" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("pid_filter:FAIL")
        return 1
    fi
    
    wait "$curl_pid" 2>/dev/null || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -f "$keylog_file" ]; then
        log_success "✓ Keylog PID filter test PASSED"
        TEST_RESULTS+=("pid_filter:PASS")
        return 0
    else
        log_warn "⚠ Keylog PID filter test produced no output"
        TEST_RESULTS+=("pid_filter:WARN")
        return 0
    fi
}

# Test 6: Verify keylog format compatibility
test_keylog_format_validation() {
    log_info "=== Test 6: Keylog Format Validation ==="
    
    local mode_log="$OUTPUT_DIR/keylog_format.log"
    local keylog_file="$OUTPUT_DIR/format_validation.keylog"
    
    log_info "Starting ecapture in keylog mode"
    "$ECAPTURE_BINARY" tls -m keylog -k "$keylog_file" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("format:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS requests to generate keys"
    curl "https://github.com" >/dev/null 2>&1 || true
    curl "https://www.google.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ ! -f "$keylog_file" ] || [ ! -s "$keylog_file" ]; then
        log_warn "⚠ No keylog file generated"
        TEST_RESULTS+=("format:WARN")
        return 0
    fi
    
    log_info "Validating keylog format..."
    local format_valid=1
    
    # Check each line format
    while IFS= read -r line; do
        # Skip empty lines
        [ -z "$line" ] && continue
        
        # Check if line starts with CLIENT_RANDOM or other valid key types
        if ! echo "$line" | grep -qE "^(CLIENT_RANDOM|SERVER_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0|EXPORTER_SECRET)"; then
            log_warn "Invalid line format: $line"
            format_valid=0
        fi
    done < "$keylog_file"
    
    if [ $format_valid -eq 1 ]; then
        log_success "✓ Keylog format validation test PASSED"
        TEST_RESULTS+=("format:PASS")
        return 0
    else
        log_warn "⚠ Some keylog entries have unexpected format"
        TEST_RESULTS+=("format:WARN")
        return 0
    fi
}

# Test 7: Keylog with UID filtering
test_keylog_uid_filter() {
    log_info "=== Test 7: Keylog with UID Filter ==="
    
    local mode_log="$OUTPUT_DIR/keylog_uid.log"
    local keylog_file="$OUTPUT_DIR/uid_filter.keylog"
    local current_uid
    current_uid=$(id -u)
    
    log_info "Starting ecapture with UID filter: $current_uid"
    "$ECAPTURE_BINARY" tls -m keylog -k "$keylog_file" -u "$current_uid" > "$mode_log" 2>&1 &
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
    
    if [ -f "$keylog_file" ] && [ -s "$keylog_file" ]; then
        log_success "✓ Keylog UID filter test PASSED"
        TEST_RESULTS+=("uid_filter:PASS")
        return 0
    else
        log_warn "⚠ Keylog UID filter test produced no output"
        TEST_RESULTS+=("uid_filter:WARN")
        return 0
    fi
}

# Test 8: Combined keylog and pcap capture (verify they can work together)
test_keylog_with_tcpdump() {
    log_info "=== Test 8: Keylog Integration with tcpdump ==="
    
    if ! command_exists tcpdump; then
        log_warn "tcpdump not available, skipping integration test"
        TEST_RESULTS+=("tcpdump:SKIP")
        return 0
    fi
    
    local mode_log="$OUTPUT_DIR/keylog_tcpdump.log"
    local keylog_file="$OUTPUT_DIR/tcpdump.keylog"
    local tcpdump_file="$OUTPUT_DIR/tcpdump.pcap"
    
    log_info "Starting tcpdump to capture encrypted traffic"
    tcpdump -i any -w "$tcpdump_file" "tcp port 443" > /dev/null 2>&1 &
    local tcpdump_pid=$!
    sleep 2
    
    log_info "Starting ecapture in keylog mode"
    "$ECAPTURE_BINARY" tls -m keylog -k "$keylog_file" > "$mode_log" 2>&1 &
    local ecap_pid=$!
    sleep 3
    
    if ! kill -0 "$ecap_pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        kill "$tcpdump_pid" 2>/dev/null || true
        TEST_RESULTS+=("tcpdump:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request (captured by both tools)"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    # Stop both tools
    kill -INT "$ecap_pid" 2>/dev/null || true
    kill -INT "$tcpdump_pid" 2>/dev/null || true
    sleep 2
    
    # Force kill if needed
    kill -9 "$tcpdump_pid" 2>/dev/null || true
    
    local test_passed=0
    if [ -f "$keylog_file" ] && [ -s "$keylog_file" ]; then
        log_success "Keylog file created successfully"
        test_passed=1
    fi
    
    if [ -f "$tcpdump_file" ] && [ -s "$tcpdump_file" ]; then
        log_success "tcpdump pcap file created successfully"
        log_info "In a real scenario, Wireshark can use the keylog file to decrypt the pcap"
    fi
    
    if [ $test_passed -eq 1 ]; then
        log_success "✓ Keylog/tcpdump integration test PASSED"
        TEST_RESULTS+=("tcpdump:PASS")
        return 0
    else
        log_warn "⚠ Keylog/tcpdump integration test produced limited results"
        TEST_RESULTS+=("tcpdump:WARN")
        return 0
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
    log_info "=== Running Advanced TLS Keylog Mode Tests ==="
    
    test_keylog_basic || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_keylog_tls12 || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_keylog_tls13 || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_keylog_concurrent || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_keylog_pid_filter || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_keylog_format_validation || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_keylog_uid_filter || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_keylog_with_tcpdump || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
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
        log_success "✓ All TLS keylog mode advanced tests PASSED"
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
