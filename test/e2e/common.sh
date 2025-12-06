#!/usr/bin/env bash
# File: test/e2e/common.sh
# Common utilities for ecapture e2e tests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This test requires root privileges. Please run with sudo."
        return 1
    fi
    return 0
}

# Check kernel version
check_kernel_version() {
    local required_major=${1:-4}
    local required_minor=${2:-18}
    
    local kernel_version
    kernel_version=$(uname -r | cut -d'.' -f1,2)
    local major minor
    major=$(echo "$kernel_version" | cut -d'.' -f1)
    minor=$(echo "$kernel_version" | cut -d'.' -f2)
    
    if [ "$major" -lt "$required_major" ] || \
       { [ "$major" -eq "$required_major" ] && [ "$minor" -lt "$required_minor" ]; }; then
        log_error "Kernel version $kernel_version is too old. Required: >= ${required_major}.${required_minor}"
        return 1
    fi
    
    log_info "Kernel version: $kernel_version (OK)"
    return 0
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    local missing_tools=()
    
    for tool in "$@"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        return 1
    fi
    
    log_info "All required tools are present"
    return 0
}

# Generate self-signed certificate
generate_certificate() {
    local cert_dir="$1"
    local cert_name="${2:-server}"
    
    mkdir -p "$cert_dir"
    
    local key_file="$cert_dir/${cert_name}.key"
    local cert_file="$cert_dir/${cert_name}.crt"
    
    if [ -f "$key_file" ] && [ -f "$cert_file" ]; then
        log_info "Certificate already exists: $cert_file"
        echo "$cert_file:$key_file"
        return 0
    fi
    
    log_info "Generating self-signed certificate..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$key_file" \
        -out "$cert_file" \
        -days 365 \
        -subj "/C=US/ST=Test/L=Test/O=eCapture/CN=localhost" \
        >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        log_success "Certificate generated: $cert_file"
        echo "$cert_file:$key_file"
        return 0
    else
        log_error "Failed to generate certificate"
        return 1
    fi
}

# Wait for process to start
wait_for_process() {
    local process_name="$1"
    local timeout="${2:-10}"
    local count=0
    
    log_info "Waiting for process '$process_name' to start..."
    while [ $count -lt "$timeout" ]; do
        if pgrep -f "$process_name" >/dev/null 2>&1; then
            log_success "Process '$process_name' is running"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    log_error "Process '$process_name' did not start within ${timeout}s"
    return 1
}

# Wait for port to be open
wait_for_port() {
    local port="$1"
    local timeout="${2:-10}"
    local count=0
    
    log_info "Waiting for port $port to be open..."
    while [ $count -lt "$timeout" ]; do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            log_success "Port $port is open"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    log_error "Port $port did not open within ${timeout}s"
    return 1
}

# Kill process by PID file
kill_by_pidfile() {
    local pidfile="$1"
    
    if [ ! -f "$pidfile" ]; then
        log_warn "PID file not found: $pidfile"
        return 0
    fi
    
    local pid
    pid=$(cat "$pidfile")
    
    if [ -z "$pid" ]; then
        log_warn "Empty PID file: $pidfile"
        rm -f "$pidfile"
        return 0
    fi
    
    if kill -0 "$pid" 2>/dev/null; then
        log_info "Killing process $pid..."
        kill "$pid" 2>/dev/null || true
        sleep 1
        
        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            log_warn "Force killing process $pid..."
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi
    
    rm -f "$pidfile"
}

# Kill process by name pattern
kill_by_pattern() {
    local pattern="$1"
    local pids
    
    pids=$(pgrep -f "$pattern" 2>/dev/null || true)
    
    if [ -z "$pids" ]; then
        log_info "No processes matching '$pattern' found"
        return 0
    fi
    
    log_info "Killing processes matching '$pattern': $pids"
    for pid in $pids; do
        kill "$pid" 2>/dev/null || true
    done
    
    sleep 1
    
    # Force kill if still running
    pids=$(pgrep -f "$pattern" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        log_warn "Force killing processes: $pids"
        for pid in $pids; do
            kill -9 "$pid" 2>/dev/null || true
        done
    fi
}

# Cleanup function template
cleanup_handler() {
    log_info "Cleaning up..."
}

# Setup trap for cleanup
setup_cleanup_trap() {
    trap cleanup_handler EXIT INT TERM
}

# Verify text in output
verify_text_in_output() {
    local output_file="$1"
    local search_text="$2"
    local description="${3:-text}"
    
    if [ ! -f "$output_file" ]; then
        log_error "Output file not found: $output_file"
        return 1
    fi
    
    if grep -q "$search_text" "$output_file"; then
        log_success "Found $description in output"
        return 0
    else
        log_error "Did not find $description in output"
        log_info "Output file content:"
        cat "$output_file"
        return 1
    fi
}

# Start HTTPS server with Python
start_python_https_server() {
    local port="$1"
    local cert_file="$2"
    local key_file="$3"
    local pidfile="$4"
    local logfile="$5"
    
    log_info "Starting Python HTTPS server on port $port..."
    
    python3 -c "
import http.server
import ssl
import sys

server_address = ('127.0.0.1', $port)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                                server_side=True,
                                certfile='$cert_file',
                                keyfile='$key_file',
                                ssl_version=ssl.PROTOCOL_TLS)
print('Server started on port $port', file=sys.stderr, flush=True)
httpd.serve_forever()
" > "$logfile" 2>&1 &
    
    echo $! > "$pidfile"
    log_info "Python HTTPS server PID: $(cat "$pidfile")"
}

# Build ecapture binary if needed
build_ecapture() {
    local binary="$1"
    
    if [ -x "$binary" ]; then
        log_info "ecapture binary already exists: $binary"
        return 0
    fi
    
    log_info "Building ecapture binary..."
    
    local root_dir
    root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
    cd "$root_dir"
    
    if make all -j 4 >/dev/null 2>&1; then
        log_success "Build succeeded with 'make all'"
        return 0
    fi
    
    log_warn "'make all' failed, trying 'make nocore'..."
    if make nocore -j 4 >/dev/null 2>&1; then
        log_success "Build succeeded with 'make nocore'"
        return 0
    fi
    
    log_error "Failed to build ecapture"
    return 1
}

# Extract plaintext from ecapture output
extract_plaintext() {
    local output_file="$1"
    local pattern="${2:-GET|POST|HTTP}"
    
    grep -E "$pattern" "$output_file" || true
}
