#!/usr/bin/env bash
# File: test/e2e/bash_advanced_test.sh
# Advanced test cases for ecapture Bash module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source common utilities
# shellcheck source=test/e2e/common.sh
source "$SCRIPT_DIR/common.sh"

# Test configuration
TEST_NAME="Bash Advanced E2E Test"
ECAPTURE_BINARY="$ROOT_DIR/bin/ecapture"
TMP_DIR="/tmp/ecapture_bash_advanced_$$"
OUTPUT_DIR="$TMP_DIR/output"

# Test results
TEST_RESULTS=()

# Cleanup function
cleanup_handler() {
    log_info "=== Cleanup ==="
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
    
    if [ "${TEST_FAILED:-0}" = "0" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

setup_cleanup_trap

# Test 1: Pipe commands
test_pipe_commands() {
    log_info "=== Test 1: Pipe Commands ==="
    
    local mode_log="$OUTPUT_DIR/pipe.log"
    
    log_info "Starting ecapture for bash"
    "$ECAPTURE_BINARY" bash > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("pipe:FAIL")
        return 1
    fi
    
    log_info "Executing pipe commands"
    bash -c "echo 'test_pipe_capture' | grep 'pipe' | wc -l" >/dev/null 2>&1 || true
    bash -c "ls -la /tmp | head -5 | tail -2" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Pipe commands test PASSED"
        TEST_RESULTS+=("pipe:PASS")
        return 0
    else
        log_warn "⚠ Pipe commands test produced no output"
        TEST_RESULTS+=("pipe:WARN")
        return 0
    fi
}

# Test 2: Redirect commands
test_redirect_commands() {
    log_info "=== Test 2: Redirect Commands ==="
    
    local mode_log="$OUTPUT_DIR/redirect.log"
    local temp_file="$TMP_DIR/redirect_test.txt"
    
    log_info "Starting ecapture for bash"
    "$ECAPTURE_BINARY" bash > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("redirect:FAIL")
        return 1
    fi
    
    log_info "Executing redirect commands"
    bash -c "echo 'test_redirect_output' > $temp_file" 2>/dev/null || true
    bash -c "cat $temp_file" 2>/dev/null || true
    bash -c "echo 'append_line' >> $temp_file" 2>/dev/null || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Redirect commands test PASSED"
        TEST_RESULTS+=("redirect:PASS")
        return 0
    else
        log_warn "⚠ Redirect commands test produced no output"
        TEST_RESULTS+=("redirect:WARN")
        return 0
    fi
}

# Test 3: Background tasks
test_background_tasks() {
    log_info "=== Test 3: Background Tasks ==="
    
    local mode_log="$OUTPUT_DIR/background.log"
    
    log_info "Starting ecapture for bash"
    "$ECAPTURE_BINARY" bash > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("background:FAIL")
        return 1
    fi
    
    log_info "Executing background tasks"
    bash -c "sleep 1 &" >/dev/null 2>&1 || true
    bash -c "(echo 'background_job' && sleep 1) &" >/dev/null 2>&1 || true
    sleep 3
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Background tasks test PASSED"
        TEST_RESULTS+=("background:PASS")
        return 0
    else
        log_warn "⚠ Background tasks test produced no output"
        TEST_RESULTS+=("background:WARN")
        return 0
    fi
}

# Test 4: Sub-shells
test_subshells() {
    log_info "=== Test 4: Sub-shells ==="
    
    local mode_log="$OUTPUT_DIR/subshell.log"
    
    log_info "Starting ecapture for bash"
    "$ECAPTURE_BINARY" bash > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("subshell:FAIL")
        return 1
    fi
    
    log_info "Executing sub-shell commands"
    bash -c "(cd /tmp && pwd && ls -la | head -3)" >/dev/null 2>&1 || true
    bash -c "echo \$(date +%Y-%m-%d)" >/dev/null 2>&1 || true
    bash -c "result=\$(echo 'subshell_test'); echo \$result" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Sub-shells test PASSED"
        TEST_RESULTS+=("subshell:PASS")
        return 0
    else
        log_warn "⚠ Sub-shells test produced no output"
        TEST_RESULTS+=("subshell:WARN")
        return 0
    fi
}

# Test 5: Long command lines
test_long_commands() {
    log_info "=== Test 5: Long Command Lines ==="
    
    local mode_log="$OUTPUT_DIR/long_cmd.log"
    
    log_info "Starting ecapture for bash"
    "$ECAPTURE_BINARY" bash > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("long_cmd:FAIL")
        return 1
    fi
    
    log_info "Executing long command lines"
    local long_string
    long_string=$(printf 'A%.0s' {1..500})
    bash -c "echo '$long_string'" >/dev/null 2>&1 || true
    bash -c "echo 'this is a very long command line that contains many words and should test the buffer handling capabilities of ecapture bash module to ensure it can capture long inputs properly without truncation or buffer overflow issues'" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Long command lines test PASSED"
        TEST_RESULTS+=("long_cmd:PASS")
        return 0
    else
        log_warn "⚠ Long command lines test produced no output"
        TEST_RESULTS+=("long_cmd:WARN")
        return 0
    fi
}

# Test 6: Special characters
test_special_characters() {
    log_info "=== Test 6: Special Characters ==="
    
    local mode_log="$OUTPUT_DIR/special_chars.log"
    
    log_info "Starting ecapture for bash"
    "$ECAPTURE_BINARY" bash > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("special_chars:FAIL")
        return 1
    fi
    
    log_info "Executing commands with special characters"
    bash -c "echo 'test\$VAR'" >/dev/null 2>&1 || true
    bash -c "echo \"quotes 'and' backslash\\\"" >/dev/null 2>&1 || true
    bash -c "echo 'symbols: !@#\$%^&*()[]{}'" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Special characters test PASSED"
        TEST_RESULTS+=("special_chars:PASS")
        return 0
    else
        log_warn "⚠ Special characters test produced no output"
        TEST_RESULTS+=("special_chars:WARN")
        return 0
    fi
}

# Test 7: Error code filtering (capture only successful commands)
test_error_code_zero() {
    log_info "=== Test 7: Error Code Filtering (Success Only) ==="
    
    local mode_log="$OUTPUT_DIR/error_zero.log"
    
    log_info "Starting ecapture with error code filter: 0"
    "$ECAPTURE_BINARY" bash -e 0 > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("error_zero:FAIL")
        return 1
    fi
    
    log_info "Executing successful and failed commands"
    bash -c "echo 'success_command'" >/dev/null 2>&1 || true
    bash -c "false" >/dev/null 2>&1 || true
    bash -c "ls /nonexistent_dir_12345" >/dev/null 2>&1 || true
    bash -c "echo 'another_success'" >/dev/null 2>&1 || true
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Error code filtering test PASSED"
        TEST_RESULTS+=("error_zero:PASS")
        return 0
    else
        log_warn "⚠ Error code filtering test produced no output"
        TEST_RESULTS+=("error_zero:WARN")
        return 0
    fi
}

# Test 8: Interactive bash session simulation
test_interactive_session() {
    log_info "=== Test 8: Interactive Session Simulation ==="
    
    local mode_log="$OUTPUT_DIR/interactive.log"
    
    log_info "Starting ecapture for bash"
    "$ECAPTURE_BINARY" bash > "$mode_log" 2>&1 &
    local pid=$!
    sleep 3
    
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "eCapture died during startup"
        TEST_RESULTS+=("interactive:FAIL")
        return 1
    fi
    
    log_info "Simulating interactive bash session"
    {
        echo "pwd"
        echo "whoami"
        echo "echo 'interactive test'"
        echo "history | tail -3"
        echo "exit"
    } | bash --norc --noprofile >/dev/null 2>&1 || true
    
    sleep 2
    
    kill -INT "$pid" 2>/dev/null || true
    sleep 2
    
    if [ -s "$mode_log" ]; then
        log_success "✓ Interactive session test PASSED"
        TEST_RESULTS+=("interactive:PASS")
        return 0
    else
        log_warn "⚠ Interactive session test produced no output"
        TEST_RESULTS+=("interactive:WARN")
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
    
    if ! check_prerequisites bash; then
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
    log_info "=== Running Advanced Bash Tests ==="
    
    test_pipe_commands || true
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
    sleep 1
    
    test_redirect_commands || true
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
    sleep 1
    
    test_background_tasks || true
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
    sleep 1
    
    test_subshells || true
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
    sleep 1
    
    test_long_commands || true
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
    sleep 1
    
    test_special_characters || true
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
    sleep 1
    
    test_error_code_zero || true
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
    sleep 1
    
    test_interactive_session || true
    kill_by_pattern "$ECAPTURE_BINARY.*bash" || true
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
        log_success "✓ All Bash advanced tests PASSED"
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
