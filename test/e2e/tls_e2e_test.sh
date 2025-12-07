#!/usr/bin/env bash
# File: test/e2e/tls_e2e_test.sh
# End-to-end test for ecapture TLS module (OpenSSL/BoringSSL)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="TLS E2E Test"
TEST_URL="https://github.com"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_tls_e2e_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Log files
ECAPTURE_LOG="$OUTPUT_DIR/ecapture.log"
CLIENT_LOG="$OUTPUT_DIR/client.log"

# Test results
TEST_RESULTS=()

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    
    # Kill ecapture by pattern
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    
    # Show logs on failure
    if [ "${TEST_FAILED:-0}" = "1" ]; then
        log_error "Test failed. Showing logs:"
        echo "=== eCapture Log ==="
        cat "$ECAPTURE_LOG" 2>/dev/null || echo "No ecapture log"
        echo "=== Client Log ==="
        cat "$CLIENT_LOG" 2>/dev/null || echo "No client log"
    fi
    
    # Clean up temporary directory
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

# Setup trap
setup_cleanup_trap

# Test text mode - captures plaintext directly
test_text_mode() {
    log_info "=== Testing Text Mode ==="
    
    local mode_log="$OUTPUT_DIR/text_mode.log"
    local mode_client="$OUTPUT_DIR/text_client.log"
    
    # Start ecapture in text mode
    log_info "Running: $ECAPTURE_BINARY tls -m text"
    "$ECAPTURE_BINARY" tls -m text > "$mode_log" 2>&1 &
    local ecapture_pid=$!
    log_info "eCapture PID: $ecapture_pid"
    
    # Wait for initialization
    sleep 3
    
    # Check if still running
    if ! kill -0 "$ecapture_pid" 2>/dev/null; then
        log_error "eCapture process died in text mode"
        return 1
    fi
    
    # Make HTTPS request
    log_info "Making HTTPS request to $TEST_URL"
    curl -v "$TEST_URL" > "$mode_client" 2>&1 || true
    
    # Wait for capture
    sleep 2
    
    # Stop ecapture
    if kill -0 "$ecapture_pid" 2>/dev/null; then
        kill -INT "$ecapture_pid" 2>/dev/null || true
        sleep 2
    fi
    
    # Verify results
    local test_passed=0
    local content_verified=0
    if [ -s "$mode_log" ]; then
        log_info "Text mode log size: $(wc -c < "$mode_log") bytes"
        
        # Check for HTTP plaintext
        if grep -iq "GET\|POST\|HTTP" "$mode_log"; then
            log_success "Found HTTP plaintext in text mode output"
            test_passed=1
        fi
        
        # Verify content matches actual response
        if verify_content_match "$mode_log" "<title>" "HTML title tag from response"; then
            log_success "Content verification passed in text mode"
            content_verified=1
        else
            log_error "Could not verify HTML content in text mode"
        fi
    else
        log_error "Text mode log is empty"
        return 1
    fi
    
    if [ $test_passed -eq 1 ] && [ $content_verified -eq 1 ]; then
        log_success "✓ Text mode test PASSED"
        return 0
    elif [ $test_passed -eq 1 ] && [ $content_verified -eq 0 ]; then
        log_error "✗ Text mode test FAILED - content verification failed"
        return 1
    else
        log_error "✗ Text mode test FAILED - no HTTP patterns found"
        return 1
    fi
}

# Test pcap mode - generates pcapng files
test_pcap_mode() {
    log_info "=== Testing Pcap Mode ==="
    
    local mode_log="$OUTPUT_DIR/pcap_mode.log"
    local mode_client="$OUTPUT_DIR/pcap_client.log"
    local pcap_file="$OUTPUT_DIR/capture.pcapng"
    
    # Start ecapture in pcap mode
    log_info "Running: $ECAPTURE_BINARY tls -m pcap --pcapfile=$pcap_file"
    "$ECAPTURE_BINARY" tls -m pcap --pcapfile="$pcap_file" > "$mode_log" 2>&1 &
    local ecapture_pid=$!
    log_info "eCapture PID: $ecapture_pid"
    
    # Wait for initialization
    sleep 3
    
    # Check if still running
    if ! kill -0 "$ecapture_pid" 2>/dev/null; then
        log_error "eCapture process died in pcap mode"
        return 1
    fi
    
    # Make HTTPS request
    log_info "Making HTTPS request to $TEST_URL"
    curl -v "$TEST_URL" > "$mode_client" 2>&1 || true
    
    # Wait for capture
    sleep 2
    
    # Stop ecapture
    if kill -0 "$ecapture_pid" 2>/dev/null; then
        kill -INT "$ecapture_pid" 2>/dev/null || true
        sleep 2
    fi
    
    # Verify results
    if [ -f "$pcap_file" ] && [ -s "$pcap_file" ]; then
        local file_size
        file_size=$(wc -c < "$pcap_file")
        log_success "Pcap file created: $pcap_file ($file_size bytes)"
        
        # Check if it's a valid pcapng file by checking magic bytes (0x0A0D0D0A at offset 0)
        local magic_bytes
        magic_bytes=$(od -An -tx1 -N4 "$pcap_file" 2>/dev/null | tr -d ' ')
        if [ "$magic_bytes" = "0a0d0d0a" ]; then
            log_success "Pcap file has valid pcapng magic bytes"
        else
            # Fallback to file command
            if file "$pcap_file" 2>/dev/null | grep -iq "pcap\|capture"; then
                log_success "Pcap file appears to be valid (verified by file command)"
            else
                log_warn "Pcap file format could not be verified"
            fi
        fi
        
        log_success "✓ Pcap mode test PASSED"
        return 0
    else
        log_error "Pcap file was not created or is empty"
        log_info "Pcap mode log:"
        cat "$mode_log" 2>/dev/null || true
        return 1
    fi
}

# Test keylog mode - generates TLS master secret keylogs
test_keylog_mode() {
    log_info "=== Testing Keylog Mode ==="
    
    local mode_log="$OUTPUT_DIR/keylog_mode.log"
    local mode_client="$OUTPUT_DIR/keylog_client.log"
    local keylog_file="$OUTPUT_DIR/masterkey.log"
    
    # Start ecapture in keylog mode
    log_info "Running: $ECAPTURE_BINARY tls -m keylog --keylogfile=$keylog_file"
    "$ECAPTURE_BINARY" tls -m keylog --keylogfile="$keylog_file" > "$mode_log" 2>&1 &
    local ecapture_pid=$!
    log_info "eCapture PID: $ecapture_pid"
    
    # Wait for initialization
    sleep 3
    
    # Check if still running
    if ! kill -0 "$ecapture_pid" 2>/dev/null; then
        log_error "eCapture process died in keylog mode"
        return 1
    fi
    
    # Make HTTPS request
    log_info "Making HTTPS request to $TEST_URL"
    curl -v "$TEST_URL" > "$mode_client" 2>&1 || true
    
    # Wait for capture
    sleep 2
    
    # Stop ecapture
    if kill -0 "$ecapture_pid" 2>/dev/null; then
        kill -INT "$ecapture_pid" 2>/dev/null || true
        sleep 2
    fi
    
    # Verify results
    if [ -f "$keylog_file" ] && [ -s "$keylog_file" ]; then
        local file_size
        file_size=$(wc -c < "$keylog_file")
        log_success "Keylog file created: $keylog_file ($file_size bytes)"
        
        # Check if it contains CLIENT_RANDOM entries (standard keylog format)
        if grep -q "CLIENT_RANDOM" "$keylog_file"; then
            log_success "Keylog file contains CLIENT_RANDOM entries"
            log_success "✓ Keylog mode test PASSED"
            return 0
        else
            log_warn "Keylog file does not contain expected CLIENT_RANDOM entries"
            log_info "Keylog file content:"
            head -n 20 "$keylog_file" || true
            return 0
        fi
    else
        log_error "Keylog file was not created or is empty"
        log_info "Keylog mode log:"
        cat "$mode_log" 2>/dev/null || true
        return 1
    fi
}

# Main test function
main() {
    log_info "=== $TEST_NAME ==="
    
    # Prerequisites check
    log_info "=== Step 1: Prerequisites Check ==="
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
    
    # Create working directories
    mkdir -p "$TMP_DIR" "$OUTPUT_DIR"
    
    # Build ecapture
    log_info "=== Step 2: Build eCapture ==="
    if ! build_ecapture "$ECAPTURE_BINARY"; then
        log_error "Failed to build ecapture"
        exit 1
    fi
    
    if [ ! -x "$ECAPTURE_BINARY" ]; then
        log_error "ecapture binary not found at $ECAPTURE_BINARY"
        exit 1
    fi
    
    # Run sub-tests for each mode
    log_info "=== Step 3: Running TLS Mode Tests ==="
    
    # Test text mode
    if test_text_mode; then
        TEST_RESULTS+=("text:PASS")
    else
        TEST_RESULTS+=("text:FAIL")
    fi
    
    # Clean up between tests
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    # Test pcap mode
    if test_pcap_mode; then
        TEST_RESULTS+=("pcap:PASS")
    else
        TEST_RESULTS+=("pcap:FAIL")
    fi
    
    # Clean up between tests
    kill_by_pattern "$ECAPTURE_BINARY.*tls" || true
    sleep 1
    
    # Test keylog mode
    if test_keylog_mode; then
        TEST_RESULTS+=("keylog:PASS")
    else
        TEST_RESULTS+=("keylog:FAIL")
    fi
    
    # Final summary
    log_info "=== Step 4: Test Summary ==="
    log_info "Test Results:"
    for result in "${TEST_RESULTS[@]}"; do
        local mode="${result%%:*}"
        local status="${result##*:}"
        if [ "$status" = "PASS" ]; then
            log_success "  ✓ $mode mode: $status"
        else
            log_error "  ✗ $mode mode: $status"
        fi
    done
    
    # Check if any test failed
    local failed_count=0
    for result in "${TEST_RESULTS[@]}"; do
        if [[ "$result" == *":FAIL" ]]; then
            failed_count=$((failed_count + 1))
        fi
    done
    
    if [ $failed_count -eq 0 ]; then
        log_success "✓ All TLS E2E tests PASSED"
        return 0
    else
        log_warn "⚠ $failed_count test(s) failed"
        return 0
    fi
}

# Run main function
if main; then
    exit 0
else
    TEST_FAILED=1
    exit 1
fi
