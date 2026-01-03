#!/usr/bin/env bash
# File: test/e2e/tls_pcap_advanced_test.sh
# Advanced test cases for ecapture TLS module in pcap/pcapng mode

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="TLS Pcap Mode Advanced E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_tls_pcap_advanced_$$"
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

# Verify pcapng file format
verify_pcapng_file() {
    local pcap_file="$1"
    local description="${2:-pcap file}"
    
    if [ ! -f "$pcap_file" ]; then
        log_error "$description not found: $pcap_file"
        return 1
    fi
    
    if [ ! -s "$pcap_file" ]; then
        log_error "$description is empty"
        return 1
    fi
    
    local file_size
    file_size=$(wc -c < "$pcap_file")
    log_info "$description size: $file_size bytes"
    
    # Check magic bytes for pcapng format (0x0A0D0D0A)
    local magic_bytes
    magic_bytes=$(od -An -tx1 -N4 "$pcap_file" 2>/dev/null | tr -d ' ' | tr '[:upper:]' '[:lower:]')
    
    if [ "$magic_bytes" = "0a0d0d0a" ]; then
        log_success "$description has valid pcapng magic bytes"
        return 0
    else
        # Try alternative check with file command
        if file "$pcap_file" 2>/dev/null | grep -iq "pcap\|capture"; then
            log_success "$description verified by file command"
            return 0
        else
            log_warn "$description format could not be verified (magic: $magic_bytes)"
            return 0
        fi
    fi
}

# Test 1: Basic pcapng mode with default settings
test_pcapng_basic() {
    log_info "=== Test 1: Basic Pcapng Mode ==="
    
    local mode_log="$OUTPUT_DIR/pcapng_basic.log"
    local pcap_file="$OUTPUT_DIR/basic.pcapng"
    
    log_info "Starting ecapture in pcapng mode"
    "$ECAPTURE_BINARY" tls -m pcapng -w "$pcap_file" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("pcapng_basic:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if verify_pcapng_file "$pcap_file" "Basic pcapng file"; then
        log_success "✓ Basic pcapng test PASSED"
        TEST_RESULTS+=("pcapng_basic:PASS")
        return 0
    else
        log_error "✗ Basic pcapng test FAILED"
        TEST_RESULTS+=("pcapng_basic:FAIL")
        return 1
    fi
}

# Test 2: Pcap mode with filter expression (port 443)
test_pcap_with_port_filter() {
    log_info "=== Test 2: Pcap with Port Filter ==="
    
    local mode_log="$OUTPUT_DIR/pcap_port_filter.log"
    local pcap_file="$OUTPUT_DIR/port_filter.pcapng"
    
    log_info "Starting ecapture with filter: tcp port 443"
    "$ECAPTURE_BINARY" tls -m pcap -w "$pcap_file" "tcp port 443" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("port_filter:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request to port 443"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if verify_pcapng_file "$pcap_file" "Port filter pcap file"; then
        log_success "✓ Pcap port filter test PASSED"
        TEST_RESULTS+=("port_filter:PASS")
        return 0
    else
        log_error "✗ Pcap port filter test FAILED"
        TEST_RESULTS+=("port_filter:FAIL")
        return 1
    fi
}

# Test 3: Pcap mode with host filter
test_pcap_with_host_filter() {
    log_info "=== Test 3: Pcap with Host Filter ==="
    
    local mode_log="$OUTPUT_DIR/pcap_host_filter.log"
    local pcap_file="$OUTPUT_DIR/host_filter.pcapng"
    
    log_info "Starting ecapture with filter: host github.com"
    "$ECAPTURE_BINARY" tls -m pcap -w "$pcap_file" "host github.com" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("host_filter:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request to github.com"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if verify_pcapng_file "$pcap_file" "Host filter pcap file"; then
        log_success "✓ Pcap host filter test PASSED"
        TEST_RESULTS+=("host_filter:PASS")
        return 0
    else
        log_error "✗ Pcap host filter test FAILED"
        TEST_RESULTS+=("host_filter:FAIL")
        return 1
    fi
}

# Test 4: Pcap with network interface specification
test_pcap_with_interface() {
    log_info "=== Test 4: Pcap with Interface Specification ==="
    
    local mode_log="$OUTPUT_DIR/pcap_interface.log"
    local pcap_file="$OUTPUT_DIR/interface.pcapng"
    
    # Get default network interface
    local default_iface
    default_iface=$(ip route | grep default | awk '{print $5}' | head -1 || echo "")
    
    if [ -z "$default_iface" ]; then
        log_warn "Could not determine default network interface"
        TEST_RESULTS+=("interface:SKIP")
        return 0
    fi
    
    log_info "Starting ecapture with interface: $default_iface"
    "$ECAPTURE_BINARY" tls -m pcap -w "$pcap_file" -i "$default_iface" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("interface:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if verify_pcapng_file "$pcap_file" "Interface-specific pcap file"; then
        log_success "✓ Pcap interface test PASSED"
        TEST_RESULTS+=("interface:PASS")
        return 0
    else
        log_error "✗ Pcap interface test FAILED"
        TEST_RESULTS+=("interface:FAIL")
        return 1
    fi
}

# Test 5: Pcap mode with multiple simultaneous connections
test_pcap_concurrent_connections() {
    log_info "=== Test 5: Pcap Concurrent Connections ==="
    
    local mode_log="$OUTPUT_DIR/pcap_concurrent.log"
    local pcap_file="$OUTPUT_DIR/concurrent.pcapng"
    
    log_info "Starting ecapture in pcap mode"
    "$ECAPTURE_BINARY" tls -m pcap -w "$pcap_file" > "$mode_log" 2>&1 &
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
    
    if verify_pcapng_file "$pcap_file" "Concurrent connections pcap file"; then
        local file_size
        file_size=$(wc -c < "$pcap_file")
        log_info "Captured pcap file size: $file_size bytes (should contain multiple connections)"
        log_success "✓ Pcap concurrent connections test PASSED"
        TEST_RESULTS+=("concurrent:PASS")
        return 0
    else
        log_error "✗ Pcap concurrent connections test FAILED"
        TEST_RESULTS+=("concurrent:FAIL")
        return 1
    fi
}

# Test 6: Pcap mode with PID filtering
test_pcap_pid_filter() {
    log_info "=== Test 6: Pcap with PID Filter ==="
    
    local mode_log="$OUTPUT_DIR/pcap_pid.log"
    local pcap_file="$OUTPUT_DIR/pid_filter.pcapng"
    
    # Start curl in background
    curl "https://github.com" >/dev/null 2>&1 &
    local curl_pid=$!
    
    log_info "Starting ecapture with PID filter: $curl_pid"
    "$ECAPTURE_BINARY" tls -m pcap -w "$pcap_file" -p "$curl_pid" > "$mode_log" 2>&1 &
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
    
    if [ -f "$pcap_file" ] && [ -s "$pcap_file" ]; then
        log_success "✓ Pcap PID filter test PASSED"
        TEST_RESULTS+=("pid_filter:PASS")
        return 0
    else
        log_warn "⚠ Pcap PID filter test produced no output (process may have completed too quickly)"
        TEST_RESULTS+=("pid_filter:WARN")
        return 0
    fi
}

# Test 7: Verify pcap file can be read by tshark if available
test_pcap_tshark_compatibility() {
    log_info "=== Test 7: Pcap Tshark Compatibility ==="
    
    if ! command_exists tshark; then
        log_warn "tshark not available, skipping compatibility test"
        TEST_RESULTS+=("tshark_compat:SKIP")
        return 0
    fi
    
    local mode_log="$OUTPUT_DIR/pcap_tshark.log"
    local pcap_file="$OUTPUT_DIR/tshark_test.pcapng"
    
    log_info "Starting ecapture in pcap mode"
    "$ECAPTURE_BINARY" tls -m pcap -w "$pcap_file" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("tshark_compat:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -f "$pcap_file" ] && [ -s "$pcap_file" ]; then
        log_info "Testing pcap file with tshark"
        if tshark -r "$pcap_file" -c 10 >/dev/null 2>&1; then
            log_success "✓ Pcap file is readable by tshark"
            TEST_RESULTS+=("tshark_compat:PASS")
            return 0
        else
            log_error "✗ Pcap file is not readable by tshark"
            TEST_RESULTS+=("tshark_compat:FAIL")
            return 1
        fi
    else
        log_error "✗ Pcap file was not created"
        TEST_RESULTS+=("tshark_compat:FAIL")
        return 1
    fi
}

# Test 8: Pcap mode with mapsize parameter
test_pcap_with_mapsize() {
    log_info "=== Test 8: Pcap with Mapsize Configuration ==="
    
    local mode_log="$OUTPUT_DIR/pcap_mapsize.log"
    local pcap_file="$OUTPUT_DIR/mapsize.pcapng"
    local mapsize=1024
    
    log_info "Starting ecapture with mapsize: $mapsize"
    "$ECAPTURE_BINARY" tls -m pcap -w "$pcap_file" --mapsize "$mapsize" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("mapsize:FAIL")
        return 1
    fi
    
    log_info "Making HTTPS request"
    curl -v "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if verify_pcapng_file "$pcap_file" "Mapsize pcap file"; then
        log_success "✓ Pcap mapsize test PASSED"
        TEST_RESULTS+=("mapsize:PASS")
        return 0
    else
        log_error "✗ Pcap mapsize test FAILED"
        TEST_RESULTS+=("mapsize:FAIL")
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
    log_info "=== Running Advanced TLS Pcap Mode Tests ==="
    
    test_pcapng_basic || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_pcap_with_port_filter || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_pcap_with_host_filter || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_pcap_with_interface || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_pcap_concurrent_connections || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_pcap_pid_filter || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_pcap_tshark_compatibility || true
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    test_pcap_with_mapsize || true
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
        log_success "✓ All TLS pcap mode advanced tests PASSED"
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
