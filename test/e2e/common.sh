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

# Check if a binary is linked against a specific library
check_library_linkage() {
    local binary="$1"
    local library_pattern="$2"
    local description="${3:-library}"
    
    if [ ! -f "$binary" ] && ! command_exists "$binary"; then
        log_error "Binary not found: $binary"
        return 1
    fi
    
    # Use full path if it's a command
    local binary_path="$binary"
    if ! [ -f "$binary" ]; then
        binary_path=$(command -v "$binary")
    fi
    
    log_info "Checking if $binary is linked against $description..."
    
    if ldd "$binary_path" 2>/dev/null | grep -q "$library_pattern"; then
        log_success "$binary is linked against $description"
        return 0
    else
        log_warn "$binary is NOT linked against $description"
        log_info "Libraries linked by $binary:"
        ldd "$binary_path" 2>/dev/null | head -20 || true
        return 1
    fi
}

# Verify that captured content matches expected patterns
verify_content_match() {
    local output_file="$1"
    local expected_pattern="$2"
    local description="${3:-expected content}"
    
    if [ ! -f "$output_file" ]; then
        log_error "Output file not found: $output_file"
        return 1
    fi
    
    log_info "Verifying $description in captured output..."
    
    if grep -q "$expected_pattern" "$output_file"; then
        log_success "Found $description in captured output"
        return 0
    else
        log_error "Did not find $description in captured output"
        log_info "Expected pattern: $expected_pattern"
        log_info "Sample output (first 100 lines):"
        head -n 100 "$output_file" || true
        return 1
    fi
}
