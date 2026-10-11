#!/usr/bin/env bash
# Strict captured-event destination checks for non-TLS text probes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../.." && pwd)"

# shellcheck source=test/e2e/lib/testlib.sh
source "$E2E_DIR/lib/testlib.sh"

ECAPTURE_BINARY="${ECAPTURE_BINARY:-$ROOT_DIR/bin/ecapture}"
WORK_DIR=""
CAPTURE_PID=""
CASE_DIR=""
CASE_TOKEN=""
CAPTURE_LOG=""
OPERATIONAL_LOG=""
EVENT_FILE=""
MYSQL_FIXTURE=""

stop_common_capture() {
    if [[ -z "$CAPTURE_PID" ]]; then
        return 0
    fi
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        local attempt
        for attempt in $(seq 1 40); do
            if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
    fi
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -TERM "$CAPTURE_PID" 2>/dev/null || true
        sleep 0.5
    fi
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -KILL "$CAPTURE_PID" 2>/dev/null || true
    fi
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""
}

common_config_cleanup() {
    stop_common_capture || true
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        if [[ "${E2E_KEEP_ARTIFACTS:-0}" == "1" || "$E2E_FAILED" -gt 0 ]]; then
            log_info "Preserving non-TLS eventaddr artifacts: $WORK_DIR"
        else
            rm -rf -- "$WORK_DIR"
        fi
    fi
}
trap common_config_cleanup EXIT

setup_common_config_suite() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "Non-TLS eventaddr E2E requires Linux"
        return 1
    fi
    if ((EUID != 0)); then
        log_error "Non-TLS eventaddr E2E requires root"
        return 1
    fi
    require_command bash
    require_command zsh
    require_command script
    require_command c++
    [[ -x "$ECAPTURE_BINARY" ]] || {
        log_error "eCapture binary not found: $ECAPTURE_BINARY"
        return 1
    }
    local artifact_root="${E2E_ARTIFACT_ROOT:-/tmp/ecapture-e2e}"
    mkdir -p "$artifact_root"
    WORK_DIR="$(mktemp -d "$artifact_root/common-config.XXXXXX")"
    MYSQL_FIXTURE="$WORK_DIR/mysql_dispatch_fixture"
    c++ -std=c++17 -O0 -g0 -rdynamic \
        -o "$MYSQL_FIXTURE" "$E2E_DIR/fixtures/c/mysql_dispatch_fixture.cc"
    log_info "Artifacts: $WORK_DIR"
}

prepare_common_case() {
    local module="$1"
    CASE_DIR="$WORK_DIR/$module"
    mkdir -p "$CASE_DIR"
    CASE_TOKEN="ECAPTURE_E2E_${module^^}_EVENTADDR_$$_$RANDOM"
    CAPTURE_LOG="$CASE_DIR/ecapture.stderr.log"
    OPERATIONAL_LOG="$CASE_DIR/operational.log"
    EVENT_FILE="$CASE_DIR/events.log"
}

start_common_capture() {
    local module="$1"
    shift
    : >"$CAPTURE_LOG"
    log_info "Starting strict $module eventaddr capture"
    "$ECAPTURE_BINARY" --eventaddr "$EVENT_FILE" --logaddr "$OPERATIONAL_LOG" \
        "$@" >"$CAPTURE_LOG" 2>&1 &
    CAPTURE_PID=$!

    local attempt
    for attempt in $(seq 1 50); do
        if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            wait "$CAPTURE_PID" 2>/dev/null || true
            log_error "$module probe exited during initialization"
            CAPTURE_PID=""
            return 1
        fi
        if [[ -s "$OPERATIONAL_LOG" ]] &&
            grep -Fq "probe started successfully" "$OPERATIONAL_LOG"; then
            return 0
        fi
        sleep 0.2
    done
    log_error "Timed out waiting for $module probe startup"
    return 1
}

assert_common_case() {
    local module="$1"
    assert_no_capture_errors "$CAPTURE_LOG" || return 1
    assert_file_contains "$EVENT_FILE" "$CASE_TOKEN" \
        "$module captured event token" || return 1
    assert_output_isolation "$OPERATIONAL_LOG" "$EVENT_FILE" "$CASE_TOKEN"
}

case_bash_eventaddr() {
    prepare_common_case bash
    local bash_path
    bash_path="$(command -v bash)"
    start_common_capture bash bash --bash "$bash_path" || return 1
    printf 'echo %s\nexit\n' "$CASE_TOKEN" |
        script -qefc "$bash_path --noprofile --norc -i" /dev/null \
            >"$CASE_DIR/workload.log" 2>&1 || {
        stop_common_capture
        return 1
    }
    sleep 1
    stop_common_capture
    assert_common_case bash
}

case_zsh_eventaddr() {
    prepare_common_case zsh
    local zsh_path
    zsh_path="$(command -v zsh)"
    start_common_capture zsh zsh --zsh "$zsh_path" || return 1
    printf 'echo %s\nexit\n' "$CASE_TOKEN" |
        script -qefc "$zsh_path -f -i" /dev/null \
            >"$CASE_DIR/workload.log" 2>&1 || {
        stop_common_capture
        return 1
    }
    sleep 1
    stop_common_capture
    assert_common_case zsh
}

case_mysql_eventaddr() {
    prepare_common_case mysqld
    start_common_capture mysqld mysqld --mysqld "$MYSQL_FIXTURE" || return 1
    "$MYSQL_FIXTURE" "$CASE_TOKEN" >"$CASE_DIR/workload.log" 2>&1 || {
        stop_common_capture
        return 1
    }
    sleep 1
    stop_common_capture
    assert_common_case mysqld
}

main() {
    setup_common_config_suite
    run_case "linux/bash/file-eventaddr-isolation" case_bash_eventaddr
    run_case "linux/zsh/file-eventaddr-isolation" case_zsh_eventaddr
    run_case "linux/mysqld/file-eventaddr-isolation" case_mysql_eventaddr
    print_summary "Linux non-TLS common config E2E"
}

main "$@"
