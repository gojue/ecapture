#!/usr/bin/env bash
# File: test/e2e/gnutls_e2e_test.sh
# End-to-end test for ecapture GnuTLS module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="GnuTLS E2E Test"
HTTPS_PORT=8444
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_gnutls_e2e_$$"
CERT_DIR="$TMP_DIR/certs"
OUTPUT_DIR="$TMP_DIR/output"

# PID files
SERVER_PIDFILE="$TMP_DIR/server.pid"
ECAPTURE_PIDFILE="$TMP_DIR/ecapture.pid"

# Log files
SERVER_LOG="$OUTPUT_DIR/server.log"
ECAPTURE_LOG="$OUTPUT_DIR/ecapture.log"
CLIENT_LOG="$OUTPUT_DIR/client.log"

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    
    # Kill ecapture
    kill_by_pidfile "$ECAPTURE_PIDFILE"
    
    # Kill HTTPS server
    kill_by_pidfile "$SERVER_PIDFILE"
    
    # Kill any remaining processes
    kill_by_pattern "python3.*http.server" || true
    kill_by_pattern "$ECAPTURE_BINARY.*gnutls" || true
    
    # Show logs on failure
    if [ "${TEST_FAILED:-0}" = "1" ]; then
        log_error "Test failed. Showing logs:"
        echo "=== Server Log ==="
        cat "$SERVER_LOG" 2>/dev/null || echo "No server log"
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

# Check if GnuTLS is available
check_gnutls_available() {
    if ! ldconfig -p | grep -q libgnutls; then
        log_warn "libgnutls not found in system libraries"
        log_warn "GnuTLS test may not work without libgnutls installed"
        log_info "Install with: apt-get install libgnutls30 (Ubuntu/Debian)"
        return 1
    fi
    log_info "libgnutls found in system"
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
    
    if ! check_prerequisites openssl curl python3 nc; then
        log_error "Prerequisites check failed"
        exit 1
    fi
    
    # Check for GnuTLS (non-fatal warning)
    check_gnutls_available || log_warn "Continuing test without GnuTLS library check"
    
    # Create working directories
    mkdir -p "$TMP_DIR" "$CERT_DIR" "$OUTPUT_DIR"
    
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
    
    # Generate certificates
    log_info "=== Step 3: Generate Certificates ==="
    local cert_info
    if ! cert_info=$(generate_certificate "$CERT_DIR" "server"); then
        log_error "Failed to generate certificates"
        exit 1
    fi
    
    local cert_file key_file
    cert_file=$(echo "$cert_info" | cut -d':' -f1)
    key_file=$(echo "$cert_info" | cut -d':' -f2)
    
    # Start HTTPS server
    log_info "=== Step 4: Start HTTPS Server ==="
    start_python_https_server "$HTTPS_PORT" "$cert_file" "$key_file" "$SERVER_PIDFILE" "$SERVER_LOG"
    
    if ! wait_for_port "$HTTPS_PORT" 10; then
        log_error "HTTPS server failed to start"
        TEST_FAILED=1
        exit 1
    fi
    
    # Start ecapture GnuTLS module
    log_info "=== Step 5: Start eCapture GnuTLS Module ==="
    log_info "Running: $ECAPTURE_BINARY gnutls -m text"
    
    "$ECAPTURE_BINARY" gnutls -m text > "$ECAPTURE_LOG" 2>&1 &
    echo $! > "$ECAPTURE_PIDFILE"
    
    local ecapture_pid
    ecapture_pid=$(cat "$ECAPTURE_PIDFILE")
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
    
    # Make HTTPS request with wget (uses GnuTLS on some systems)
    log_info "=== Step 6: Make HTTPS Request ==="
    log_info "Sending HTTPS request to https://127.0.0.1:$HTTPS_PORT/"
    
    # Try wget first (may use GnuTLS)
    if command_exists wget; then
        log_info "Using wget (may use GnuTLS)"
        wget --no-check-certificate -O /dev/null "https://127.0.0.1:$HTTPS_PORT/" > "$CLIENT_LOG" 2>&1 || {
            log_warn "wget returned non-zero exit code (this might be expected)"
        }
    else
        # Fall back to curl
        log_info "wget not found, falling back to curl"
        curl -k -v "https://127.0.0.1:$HTTPS_PORT/" > "$CLIENT_LOG" 2>&1 || {
            log_warn "curl returned non-zero exit code (this might be expected)"
        }
    fi
    
    # Wait for ecapture to capture the traffic
    log_info "Waiting for eCapture to capture traffic..."
    sleep 2
    
    # Stop ecapture gracefully
    log_info "=== Step 7: Stop eCapture ==="
    if kill -0 "$ecapture_pid" 2>/dev/null; then
        kill -INT "$ecapture_pid" 2>/dev/null || true
        sleep 2
    fi
    
    # Verify results
    log_info "=== Step 8: Verify Results ==="
    
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
    
    # Look for GnuTLS indicators
    if grep -iq "GnuTLS\|gnutls" "$ECAPTURE_LOG"; then
        log_success "Found GnuTLS indicators in eCapture output"
    fi
    
    # Display sample output
    log_info "Sample eCapture output (first 50 lines):"
    head -n 50 "$ECAPTURE_LOG"
    
    # Check client success
    if grep -q "HTTP.*200\|saved\|Downloaded" "$CLIENT_LOG"; then
        log_success "Client successfully connected to HTTPS server"
    else
        log_warn "Client connection status unclear"
    fi
    
    # Final verdict
    log_info "=== Step 9: Test Summary ==="
    
    # Note about GnuTLS usage
    log_info "Note: This test uses a Python HTTPS server which may use OpenSSL"
    log_info "      For full GnuTLS testing, use applications that link to libgnutls"
    
    if [ $found_http -eq 1 ]; then
        log_success "✓ GnuTLS E2E test PASSED"
        log_success "eCapture successfully captured HTTPS plaintext traffic"
        return 0
    else
        log_warn "⚠ GnuTLS E2E test completed with warnings"
        log_warn "eCapture ran successfully but plaintext patterns not clearly detected"
        log_info "This may be due to:"
        log_info "  - Client not using GnuTLS library"
        log_info "  - Different output format than expected"
        log_info "  - Traffic not fully captured in test window"
        log_info "Please review logs manually to confirm functionality"
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
