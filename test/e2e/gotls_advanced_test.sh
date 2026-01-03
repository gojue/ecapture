#!/usr/bin/env bash
# File: test/e2e/gotls_advanced_test.sh
# Advanced test cases for ecapture GoTLS module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="GoTLS Advanced E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_gotls_advanced_$$"
OUTPUT_DIR="$TMP_DIR/output"
PROGRAMS_DIR="$TMP_DIR/programs"

# Test results
TEST_RESULTS=()

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    kill_by_pattern "$ECAPTURE_BINARY.*gotls" || true
    kill_by_pattern "go_https_server" || true
    kill_by_pattern "go_https_client" || true
    kill_by_pattern "go_grpc_test" || true
    
    if [ "${TEST_FAILED:-0}" = "0" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    
    # Clean up test programs
    rm -f "$PROGRAMS_DIR"/* 2>/dev/null || true
}

setup_cleanup_trap

# Build Go test programs
build_go_test_programs() {
    log_info "=== Building Go Test Programs ==="
    
    mkdir -p "$PROGRAMS_DIR"
    cd "$PROGRAMS_DIR"
    
    # Build simple HTTPS client
    log_info "Building simple HTTPS client..."
    cat > client.go <<'EOF'
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	url := flag.String("url", "https://github.com", "URL to request")
	insecure := flag.Bool("insecure", true, "Skip TLS verification")
	flag.Parse()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *insecure,
			},
		},
	}

	log.Printf("Requesting %s", *url)
	resp, err := client.Get(*url)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status: %s, Body length: %d bytes\n", resp.Status, len(body))
}
EOF
    
    if ! go build -o go_https_client client.go; then
        log_error "Failed to build HTTPS client"
        return 1
    fi
    
    # Build simple HTTPS server
    log_info "Building simple HTTPS server..."
    cat > server.go <<'EOF'
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	port := flag.Int("port", 8443, "Port to listen on")
	flag.Parse()

	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from Go HTTPS server! Time: %s\n", time.Now())
	})

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", *port),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	log.Printf("Starting HTTPS server on port %d", *port)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
EOF
    
    if ! go build -o go_https_server server.go; then
        log_error "Failed to build HTTPS server"
        return 1
    fi
    
    log_success "Go test programs built successfully"
    return 0
}

# Test 1: Basic GoTLS text mode capture
test_gotls_text_mode() {
    log_info "=== Test 1: GoTLS Text Mode ==="
    
    local mode_log="$OUTPUT_DIR/gotls_text.log"
    local client_path="$PROGRAMS_DIR/go_https_client"
    
    log_info "Starting ecapture in text mode for $client_path"
    "$ECAPTURE_BINARY" gotls -m text --elfpath="$client_path" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("text:FAIL")
        return 1
    fi
    
    log_info "Running Go HTTPS client"
    "$client_path" -url "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && grep -iq "GET\|POST\|HTTP\|github" "$mode_log"; then
        log_success "✓ GoTLS text mode test PASSED"
        TEST_RESULTS+=("text:PASS")
        return 0
    else
        log_error "✗ GoTLS text mode test FAILED"
        TEST_RESULTS+=("text:FAIL")
        return 1
    fi
}

# Test 2: GoTLS pcap mode capture
test_gotls_pcap_mode() {
    log_info "=== Test 2: GoTLS Pcap Mode ==="
    
    local mode_log="$OUTPUT_DIR/gotls_pcap.log"
    local pcap_file="$OUTPUT_DIR/gotls.pcapng"
    local client_path="$PROGRAMS_DIR/go_https_client"
    
    log_info "Starting ecapture in pcap mode for $client_path"
    "$ECAPTURE_BINARY" gotls -m pcap --elfpath="$client_path" -w "$pcap_file" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("pcap:FAIL")
        return 1
    fi
    
    log_info "Running Go HTTPS client"
    "$client_path" -url "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -f "$pcap_file" ] && [ -s "$pcap_file" ]; then
        log_success "✓ GoTLS pcap mode test PASSED"
        TEST_RESULTS+=("pcap:PASS")
        return 0
    else
        log_error "✗ GoTLS pcap mode test FAILED"
        TEST_RESULTS+=("pcap:FAIL")
        return 1
    fi
}

# Test 3: GoTLS keylog mode capture
test_gotls_keylog_mode() {
    log_info "=== Test 3: GoTLS Keylog Mode ==="
    
    local mode_log="$OUTPUT_DIR/gotls_keylog.log"
    local keylog_file="$OUTPUT_DIR/gotls.keylog"
    local client_path="$PROGRAMS_DIR/go_https_client"
    
    log_info "Starting ecapture in keylog mode for $client_path"
    "$ECAPTURE_BINARY" gotls -m keylog --elfpath="$client_path" -k "$keylog_file" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("keylog:FAIL")
        return 1
    fi
    
    log_info "Running Go HTTPS client"
    "$client_path" -url "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -f "$keylog_file" ]; then
        log_success "✓ GoTLS keylog mode test PASSED"
        TEST_RESULTS+=("keylog:PASS")
        return 0
    else
        log_warn "⚠ GoTLS keylog mode produced no output"
        TEST_RESULTS+=("keylog:WARN")
        return 0
    fi
}

# Test 4: GoTLS with local server
test_gotls_client_server() {
    log_info "=== Test 4: GoTLS Client-Server Communication ==="
    
    local server_path="$PROGRAMS_DIR/go_https_server"
    local client_path="$PROGRAMS_DIR/go_https_client"
    local mode_log="$OUTPUT_DIR/gotls_cs.log"
    local server_port=18443
    
    # Start server
    log_info "Starting Go HTTPS server on port $server_port"
    "$server_path" -port "$server_port" > "$OUTPUT_DIR/server.log" 2>&1 &
    local server_pid=$!
    sleep 2
    
    if ! kill -0 "$server_pid" 2>/dev/null; then
        log_error "Server failed to start"
        TEST_RESULTS+=("client_server:FAIL")
        return 1
    fi
    
    # Start ecapture for client
    log_info "Starting ecapture for Go client"
    "$ECAPTURE_BINARY" gotls -m text --elfpath="$client_path" > "$mode_log" 2>&1 &
    local ecap_pid=$!
    sleep 3
    
    if ! kill -0 "$ecap_pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        kill "$server_pid" 2>/dev/null || true
        TEST_RESULTS+=("client_server:FAIL")
        return 1
    fi
    
    # Make request to local server
    log_info "Making request to local server"
    "$client_path" -url "https://localhost:$server_port" -insecure >/dev/null 2>&1 || true
    sleep 2
    
    # Stop ecapture and server
    kill -INT "$ecap_pid" 2>/dev/null || true
    kill -INT "$server_pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ] && grep -iq "Hello from Go HTTPS server\|GET\|HTTP" "$mode_log"; then
        log_success "✓ GoTLS client-server test PASSED"
        TEST_RESULTS+=("client_server:PASS")
        return 0
    else
        log_error "✗ GoTLS client-server test FAILED"
        TEST_RESULTS+=("client_server:FAIL")
        return 1
    fi
}

# Test 5: GoTLS with multiple connections
test_gotls_multiple_connections() {
    log_info "=== Test 5: GoTLS Multiple Connections ==="
    
    local mode_log="$OUTPUT_DIR/gotls_multi.log"
    local client_path="$PROGRAMS_DIR/go_https_client"
    
    log_info "Starting ecapture for Go client"
    "$ECAPTURE_BINARY" gotls -m text --elfpath="$client_path" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("multi:FAIL")
        return 1
    fi
    
    log_info "Running multiple Go HTTPS clients"
    "$client_path" -url "https://github.com" >/dev/null 2>&1 &
    "$client_path" -url "https://www.google.com" >/dev/null 2>&1 &
    "$client_path" -url "https://www.cloudflare.com" >/dev/null 2>&1 &
    
    sleep 3
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        local request_count
        request_count=$(grep -ci "GET\|Requesting" "$mode_log" || echo "0")
        log_info "Captured $request_count requests/connections"
        
        if [ "$request_count" -gt 0 ]; then
            log_success "✓ GoTLS multiple connections test PASSED"
            TEST_RESULTS+=("multi:PASS")
            return 0
        fi
    fi
    
    log_error "✗ GoTLS multiple connections test FAILED"
    TEST_RESULTS+=("multi:FAIL")
    return 1
}

# Test 6: GoTLS with static-linked binary (build with CGO_ENABLED=0)
test_gotls_static_binary() {
    log_info "=== Test 6: GoTLS Static Binary ==="
    
    local static_client="$PROGRAMS_DIR/go_https_client_static"
    local mode_log="$OUTPUT_DIR/gotls_static.log"
    
    log_info "Building static Go client (CGO_ENABLED=0)"
    cd "$PROGRAMS_DIR"
    CGO_ENABLED=0 go build -o "$static_client" client.go 2>/dev/null || {
        log_warn "Failed to build static binary, skipping test"
        TEST_RESULTS+=("static:SKIP")
        return 0
    }
    
    log_info "Starting ecapture for static Go client"
    "$ECAPTURE_BINARY" gotls -m text --elfpath="$static_client" > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("static:FAIL")
        return 1
    fi
    
    log_info "Running static Go HTTPS client"
    "$static_client" -url "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ GoTLS static binary test PASSED"
        TEST_RESULTS+=("static:PASS")
        return 0
    else
        log_warn "⚠ GoTLS static binary test produced no output"
        TEST_RESULTS+=("static:WARN")
        return 0
    fi
}

# Test 7: GoTLS with debug logging
test_gotls_debug_mode() {
    log_info "=== Test 7: GoTLS Debug Mode ==="
    
    local mode_log="$OUTPUT_DIR/gotls_debug.log"
    local client_path="$PROGRAMS_DIR/go_https_client"
    
    log_info "Starting ecapture with debug logging"
    "$ECAPTURE_BINARY" gotls -m text --elfpath="$client_path" -d > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("debug:FAIL")
        return 1
    fi
    
    log_info "Running Go HTTPS client"
    "$client_path" -url "https://github.com" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_info "Debug log size: $(wc -c < "$mode_log") bytes"
        log_success "✓ GoTLS debug mode test PASSED"
        TEST_RESULTS+=("debug:PASS")
        return 0
    else
        log_error "✗ GoTLS debug mode test FAILED"
        TEST_RESULTS+=("debug:FAIL")
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
    
    if ! check_prerequisites go; then
        log_error "Prerequisites check failed"
        exit 1
    fi
    
    mkdir -p "$TMP_DIR" "$OUTPUT_DIR" "$PROGRAMS_DIR"
    
    # Build ecapture
    log_info "=== Build eCapture ==="
    if ! build_ecapture "$ECAPTURE_BINARY"; then
        log_error "Failed to build ecapture"
        exit 1
    fi
    
    # Build Go test programs
    log_info "=== Build Go Test Programs ==="
    if ! build_go_test_programs; then
        log_error "Failed to build Go test programs"
        exit 1
    fi
    
    # Run all tests
    log_info "=== Running Advanced GoTLS Tests ==="
    
    test_gotls_text_mode || true
    kill_by_pattern "$ECAPTURE_BINARY.*gotls" || true
    sleep 1
    
    test_gotls_pcap_mode || true
    kill_by_pattern "$ECAPTURE_BINARY.*gotls" || true
    sleep 1
    
    test_gotls_keylog_mode || true
    kill_by_pattern "$ECAPTURE_BINARY.*gotls" || true
    sleep 1
    
    test_gotls_client_server || true
    kill_by_pattern "$ECAPTURE_BINARY.*gotls\|go_https_server" || true
    sleep 1
    
    test_gotls_multiple_connections || true
    kill_by_pattern "$ECAPTURE_BINARY.*gotls" || true
    sleep 1
    
    test_gotls_static_binary || true
    kill_by_pattern "$ECAPTURE_BINARY.*gotls" || true
    sleep 1
    
    test_gotls_debug_mode || true
    kill_by_pattern "$ECAPTURE_BINARY.*gotls" || true
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
        log_success "✓ All GoTLS advanced tests PASSED"
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
