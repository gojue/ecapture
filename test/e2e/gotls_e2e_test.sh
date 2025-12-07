#!/usr/bin/env bash
# File: test/e2e/gotls_e2e_test.sh
# End-to-end test for ecapture GoTLS module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="GoTLS E2E Test"
TEST_URL="https://github.com"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
GO_CLIENT="$SCRIPT_DIR/go_https_client"
TMP_DIR="/tmp/ecapture_gotls_e2e_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Log files
ECAPTURE_LOG="$OUTPUT_DIR/ecapture.log"
CLIENT_LOG="$OUTPUT_DIR/client.log"

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    
    # Kill ecapture by pattern
    kill_by_pattern "$ECAPTURE_BINARY.*gotls" || true
    
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
    
    # Clean up built Go client
    if [ -f "$GO_CLIENT" ]; then
        rm -f "$GO_CLIENT"
    fi
}

# Setup trap
setup_cleanup_trap

# Build Go test programs
build_go_programs() {
    log_info "Building Go HTTPS client..."
    
    cd "$SCRIPT_DIR"
    
    # Build client
    if [ ! -f "$GO_CLIENT" ] || [ "$SCRIPT_DIR/go_https_client.go" -nt "$GO_CLIENT" ]; then
        log_info "Building go_https_client..."
        if ! go build -o "$GO_CLIENT" go_https_client.go; then
            log_error "Failed to build go_https_client"
            return 1
        fi
    fi
    
    log_success "Go client built successfully"
    return 0
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
    
    if ! check_prerequisites go; then
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
    
    # Build Go test programs
    log_info "=== Step 3: Build Go Test Programs ==="
    if ! build_go_programs; then
        log_error "Failed to build Go test programs"
        exit 1
    fi
    
    # Start ecapture with the Go client binary path
    log_info "=== Step 4: Start eCapture GoTLS Module ==="
    log_info "Running: $ECAPTURE_BINARY gotls -m text --elfpath=$GO_CLIENT"
    
    "$ECAPTURE_BINARY" gotls -m text --elfpath="$GO_CLIENT" > "$ECAPTURE_LOG" 2>&1 &
    local ecapture_pid=$!
    
    log_info "eCapture PID: $ecapture_pid"
    
    # Wait for ecapture to initialize
    log_info "Waiting for eCapture to initialize..."
    sleep 3
    
    # Check if ecapture is still running
    if ! kill -0 "$ecapture_pid" 2>/dev/null; then
        log_error "eCapture process died"
        TEST_FAILED=1
        exit 1
    fi
    
    # Make HTTPS request using Go client
    log_info "=== Step 5: Make HTTPS Request ==="
    log_info "Sending HTTPS request to $TEST_URL using Go client"
    
    "$GO_CLIENT" -url "$TEST_URL" > "$CLIENT_LOG" 2>&1 || {
        log_warn "Go client returned non-zero exit code (this might be expected)"
    }
    
    # Wait for ecapture to capture the traffic
    log_info "Waiting for eCapture to capture traffic..."
    sleep 2
    
    # Stop ecapture gracefully
    log_info "=== Step 6: Stop eCapture ==="
    if kill -0 "$ecapture_pid" 2>/dev/null; then
        kill -INT "$ecapture_pid" 2>/dev/null || true
        sleep 2
    fi
    
    # Verify results
    log_info "=== Step 7: Verify Results ==="
    
    # Check if ecapture log has content
    if [ ! -s "$ECAPTURE_LOG" ]; then
        log_error "eCapture log is empty"
        TEST_FAILED=1
        exit 1
    fi
    
    log_info "eCapture log size: $(wc -c < "$ECAPTURE_LOG") bytes"
    
    # Look for HTTP traffic in the output
    local found_http=0
    if grep -iq "GET\|POST\|HTTP" "$ECAPTURE_LOG"; then
        log_success "Found HTTP plaintext in eCapture output"
        found_http=1
    else
        log_warn "Did not find obvious HTTP patterns in output"
    fi
    
    # Verify content matches actual HTTP response
    # GitHub's homepage contains <title>GitHub...</title>
    local content_verified=0
    if verify_content_match "$ECAPTURE_LOG" "<title>" "HTML title tag from response"; then
        log_success "Content verification passed - captured plaintext matches actual response"
        content_verified=1
    else
        log_error "Could not verify HTML title tag in captured output"
        log_error "This indicates the captured data may not match the actual HTTP response"
    fi
    
    # Look for TLS handshake indicators or other success markers
    if grep -iq "SSL\|TLS\|GoTLS\|connected\|handshake" "$ECAPTURE_LOG"; then
        log_success "Found TLS/SSL indicators in eCapture output"
    fi
    
    # Display sample output
    log_info "Sample eCapture output (first 50 lines):"
    head -n 50 "$ECAPTURE_LOG"
    
    # Check client success
    if grep -q "Response status: 200\|bytes" "$CLIENT_LOG"; then
        log_success "Client successfully connected to HTTPS server"
    else
        log_warn "Client connection status unclear"
    fi
    
    # Final verdict
    log_info "=== Step 8: Test Summary ==="
    if [ $found_http -eq 1 ] && [ $content_verified -eq 1 ]; then
        log_success "✓ GoTLS E2E test PASSED"
        log_success "eCapture successfully captured GoTLS plaintext traffic"
        return 0
    elif [ $found_http -eq 1 ] && [ $content_verified -eq 0 ]; then
        log_error "✗ GoTLS E2E test FAILED"
        log_error "HTTP patterns found but content verification failed"
        log_error "The captured data does not match the expected HTTP response content"
        TEST_FAILED=1
        exit 1
    else
        log_error "✗ GoTLS E2E test FAILED"
        log_error "eCapture did not capture expected plaintext patterns"
        log_info "This may be due to:"
        log_info "  - Different output format than expected"
        log_info "  - Traffic not fully captured in test window"
        log_info "  - Go TLS library version differences"
        TEST_FAILED=1
        exit 1
    fi
}

# Run main function
if main; then
    exit 0
else
    TEST_FAILED=1
    exit 1
fi
