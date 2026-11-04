#!/usr/bin/env bash
# Strict non-TLS event output checks and shared process lifecycle helpers.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../.." && pwd)"
# shellcheck source=test/e2e/lib/testlib.sh
source "$E2E_DIR/lib/testlib.sh"
# shellcheck source=test/e2e/linux/platform.sh
source "$SCRIPT_DIR/platform.sh"

ECAPTURE_BINARY="${ECAPTURE_BINARY:-$ROOT_DIR/bin/ecapture}"
WORK_DIR=""
CAPTURE_PID=""
CASE_DIR=""
CASE_TOKEN=""
CAPTURE_LOG=""
OPERATIONAL_LOG=""
EVENT_FILE=""
MYSQL_FIXTURE=""
WORKLOAD_PIDS=()

stop_common_capture() {
    local signal="${1:-INT}" attempt status=0 forced=0
    [[ -n "$CAPTURE_PID" ]] || return 0
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill "-$signal" "$CAPTURE_PID" 2>/dev/null || true
        for ((attempt = 0; attempt < 50; attempt++)); do
            kill -0 "$CAPTURE_PID" 2>/dev/null || break
            sleep 0.1
        done
    fi
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        forced=1
        log_error "Probe did not exit after SIG$signal"
        kill -TERM "$CAPTURE_PID" 2>/dev/null || true
        sleep 0.5
    fi
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -KILL "$CAPTURE_PID" 2>/dev/null || true
    fi
    wait "$CAPTURE_PID" 2>/dev/null || status=$?
    CAPTURE_PID=""
    if ((forced != 0 || status != 0)); then
        log_error "Capture shutdown failed (exit=$status, forced=$forced)"
        return 1
    fi
}

common_config_cleanup() {
    local status="$1" pid
    stop_common_capture || status=1
    for pid in "${WORKLOAD_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        if [[ "${E2E_KEEP_ARTIFACTS:-0}" == 1 || "$E2E_FAILED" -gt 0 || "$status" -ne 0 ]]; then
            log_info "Preserving artifacts: $WORK_DIR"
        else
            rm -rf -- "$WORK_DIR"
        fi
    fi
    return "$status"
}

setup_common_config_suite() {
    [[ -r /etc/os-release ]] || { log_error "Linux distribution information is missing"; return 1; }
    # shellcheck disable=SC1091
    source /etc/os-release
    check_linux_platform "$(uname -s)" "$ID" "$VERSION_ID" "$(uname -m)" "$(uname -r)" "$EUID" || return 1
    require_command timeout || return 1
    [[ -x "$ECAPTURE_BINARY" ]] || { log_error "eCapture binary not found: $ECAPTURE_BINARY"; return 1; }
    umask 077
    local artifact_root="${E2E_ARTIFACT_ROOT:-/tmp/ecapture-e2e}"
    mkdir -p "$artifact_root" || return 1
    WORK_DIR="$(mktemp -d "$artifact_root/non-tls.XXXXXX")" || return 1
    log_info "Artifacts: $WORK_DIR"
}

prepare_common_case() {
    local name="$1"
    # A failed prior case must not leave an attached probe for the next case.
    stop_common_capture || return 1
    CASE_DIR="$WORK_DIR/$name"
    mkdir -p "$CASE_DIR" || return 1
    CASE_TOKEN="ECAPTURE_E2E_${name^^}_$$_$RANDOM"
    CAPTURE_LOG="$CASE_DIR/ecapture.stderr.log"
    OPERATIONAL_LOG="$CASE_DIR/operational.log"
    EVENT_FILE="$CASE_DIR/events.log"
}

start_common_capture() {
    local module="$1" attempt
    shift
    : >"$CAPTURE_LOG"
    log_info "Starting strict $module capture"
    "$ECAPTURE_BINARY" --eventaddr "$EVENT_FILE" --logaddr "$OPERATIONAL_LOG" \
        "$@" >"$CAPTURE_LOG" 2>&1 &
    CAPTURE_PID=$!
    for ((attempt = 0; attempt < 50; attempt++)); do
        if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            wait "$CAPTURE_PID" 2>/dev/null || true
            CAPTURE_PID=""
            log_error "$module probe exited during initialization"
            return 1
        fi
        if [[ -s "$OPERATIONAL_LOG" ]] && grep -Fq "probe started successfully" "$OPERATIONAL_LOG"; then
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
    assert_no_capture_errors "$OPERATIONAL_LOG" || return 1
    assert_file_contains "$EVENT_FILE" "$CASE_TOKEN" "$module captured event token" || return 1
    assert_output_isolation "$OPERATIONAL_LOG" "$EVENT_FILE" "$CASE_TOKEN"
}

run_interactive_shell() {
    local shell_path="$1" flags="$2" shell_command
    printf -v shell_command '%q %s' "$shell_path" "$flags"
    timeout --signal=TERM --kill-after=2s 20s script -qefc "$shell_command" /dev/null \
        >"$CASE_DIR/workload.log" 2>&1
}

case_shell_eventaddr() {
    local module="$1" shell_path flags
    prepare_common_case "$module" || return 1
    shell_path="$(command -v "$module")" || return 1
    flags='--noprofile --norc -i'
    [[ "$module" != zsh ]] || flags='-f -i'
    start_common_capture "$module" "$module" "--$module" "$shell_path" || return 1
    printf 'echo %s\nexit\n' "$CASE_TOKEN" | run_interactive_shell "$shell_path" "$flags" || return 1
    sleep 1
    stop_common_capture || return 1
    assert_common_case "$module"
}

case_bash_commands() {
    prepare_common_case bash-commands || return 1
    local bash_path padding marker
    bash_path="$(command -v bash)" || return 1
    printf -v padding '%0500d' 0
    start_common_capture bash bash --bash "$bash_path" || return 1
    {
        printf 'echo %s_PIPE | cat\n' "$CASE_TOKEN"
        printf 'echo %s_REDIRECT > %q\n' "$CASE_TOKEN" "$CASE_DIR/redirect.txt"
        printf '(echo %s_BACKGROUND) &\nwait\n' "$CASE_TOKEN"
        printf '(echo %s_SUBSHELL)\n' "$CASE_TOKEN"
        printf 'echo "$(echo %s_SUBSTITUTION)"\n' "$CASE_TOKEN"
        printf "echo '%s_SPECIAL_!@#$%%^&*()[]{}'\n" "$CASE_TOKEN"
        printf 'echo %s_LONG_BEGIN_%s_%s_LONG_END\n' "$CASE_TOKEN" "$padding" "$CASE_TOKEN"
        printf 'echo %s_AFTER_LONG\nexit\n' "$CASE_TOKEN"
    } | run_interactive_shell "$bash_path" '--noprofile --norc -i' || return 1
    sleep 1
    stop_common_capture || return 1
    assert_common_case bash || return 1
    for marker in PIPE REDIRECT BACKGROUND SUBSHELL SUBSTITUTION SPECIAL LONG_BEGIN AFTER_LONG; do
        assert_file_contains "$EVENT_FILE" "${CASE_TOKEN}_$marker" "Bash $marker command" || return 1
    done
    # The kernel's Bash line buffer is 256 bytes: prove truncation and recovery.
    assert_file_not_contains "$EVENT_FILE" "${CASE_TOKEN}_LONG_END" "Bash over-buffer suffix"
}

case_bash_errno() {
    # Opt-in until the matching-return-value handling in bash_probe.go is fixed.
    # A failure is a real failure, never a startup-only or WARN pass.
    prepare_common_case bash-errno || return 1
    local bash_path
    bash_path="$(command -v bash)" || return 1
    start_common_capture bash bash --bash "$bash_path" --errnumber 0 || return 1
    {
        printf 'true %s_SUCCESS\n' "$CASE_TOKEN"
        printf 'false %s_FAILURE\n' "$CASE_TOKEN"
        printf 'true %s_SUCCESS_AGAIN\nexit\n' "$CASE_TOKEN"
    } | run_interactive_shell "$bash_path" '--noprofile --norc -i' || return 1
    sleep 1
    stop_common_capture || return 1
    assert_common_case bash || return 1
    assert_file_contains "$EVENT_FILE" "${CASE_TOKEN}_SUCCESS" "matching Bash return value" || return 1
    assert_file_not_contains "$EVENT_FILE" "${CASE_TOKEN}_FAILURE" "nonmatching Bash return value"
}

build_mysql_fixture() {
    require_command c++ || return 1
    MYSQL_FIXTURE="$WORK_DIR/mysql_dispatch_fixture"
    c++ -std=c++17 -O0 -g0 -rdynamic -o "$MYSQL_FIXTURE" \
        "$E2E_DIR/fixtures/c/mysql_dispatch_fixture.cc"
}

case_mysql_eventaddr() {
    prepare_common_case mysqld || return 1
    start_common_capture mysqld mysqld --mysqld "$MYSQL_FIXTURE" || return 1
    "$MYSQL_FIXTURE" "$CASE_TOKEN" >"$CASE_DIR/workload.log" 2>&1 || return 1
    sleep 1
    stop_common_capture || return 1
    assert_common_case mysqld
}

case_mysql_queries() {
    prepare_common_case mysql-queries || return 1
    local query marker padding long_query pid failed=0 index
    local -a queries=(
        "SELECT '${CASE_TOKEN}_SELECT'"
        "INSERT INTO fixture VALUES ('${CASE_TOKEN}_INSERT')"
        "UPDATE fixture SET value='${CASE_TOKEN}_UPDATE'"
        "DELETE FROM fixture WHERE value='${CASE_TOKEN}_DELETE'"
        "BEGIN; SELECT '${CASE_TOKEN}_TRANSACTION'; COMMIT"
    )
    printf -v padding '%0500d' 0
    long_query="SELECT '${CASE_TOKEN}_LONG_BEGIN_${padding}_${CASE_TOKEN}_LONG_END'"
    start_common_capture mysqld mysqld --mysqld "$MYSQL_FIXTURE" || return 1
    # These are captured dispatch_command inputs, not database execution tests.
    for query in "${queries[@]}" "$long_query" "SELECT '${CASE_TOKEN}_AFTER_LONG'"; do
        "$MYSQL_FIXTURE" "$query" >>"$CASE_DIR/workload.log" 2>&1 || return 1
    done
    for ((index = 0; index < 8; index++)); do
        "$MYSQL_FIXTURE" "SELECT '${CASE_TOKEN}_CONCURRENT_${index}'" >>"$CASE_DIR/workload.log" 2>&1 &
        WORKLOAD_PIDS+=("$!")
    done
    for pid in "${WORKLOAD_PIDS[@]}"; do
        wait "$pid" || failed=1
    done
    WORKLOAD_PIDS=()
    ((failed == 0)) || return 1
    sleep 1
    stop_common_capture || return 1
    assert_common_case mysqld || return 1
    for marker in SELECT INSERT UPDATE DELETE TRANSACTION LONG_BEGIN AFTER_LONG; do
        assert_file_contains "$EVENT_FILE" "${CASE_TOKEN}_$marker" "MySQL $marker input" || return 1
    done
    for ((index = 0; index < 8; index++)); do
        assert_file_contains "$EVENT_FILE" "${CASE_TOKEN}_CONCURRENT_${index}" "MySQL concurrent input $index" || return 1
    done
    assert_file_contains "$EVENT_FILE" "Len=256/${#long_query}" "MySQL captured/original length" || return 1
    assert_file_not_contains "$EVENT_FILE" "${CASE_TOKEN}_LONG_END" "MySQL over-buffer suffix"
}

main() {
    local modules="${E2E_NON_TLS_MODULES:-bash zsh mysqld}" module
    [[ -n "${modules//[[:space:]]/}" ]] || { log_error "E2E_NON_TLS_MODULES must contain a module"; return 1; }
    [[ "${E2E_NON_TLS_ADVANCED:-0}" =~ ^[01]$ && "${E2E_BASH_ERRNO:-0}" =~ ^[01]$ ]] || {
        log_error "E2E_NON_TLS_ADVANCED and E2E_BASH_ERRNO must be 0 or 1"; return 1;
    }
    for module in $modules; do
        case "$module" in bash|zsh|mysqld) ;; *) log_error "Unknown non-TLS module: $module"; return 1 ;; esac
    done
    setup_common_config_suite || return 1
    for module in $modules; do
        case "$module" in
            bash|zsh)
                require_command "$module" || return 1
                require_command script || return 1
                run_case "linux/$module/file-eventaddr-isolation" case_shell_eventaddr "$module"
                if [[ "$module" == bash && "${E2E_NON_TLS_ADVANCED:-0}" == 1 ]]; then
                    run_case "linux/bash/interactive-command-shapes" case_bash_commands
                fi
                if [[ "$module" == bash && "${E2E_BASH_ERRNO:-0}" == 1 ]]; then
                    run_case "linux/bash/return-value-filter" case_bash_errno
                fi
                ;;
            mysqld)
                build_mysql_fixture || return 1
                run_case "linux/mysqld/file-eventaddr-isolation" case_mysql_eventaddr
                if [[ "${E2E_NON_TLS_ADVANCED:-0}" == 1 ]]; then
                    run_case "linux/mysqld/query-shapes-length-concurrency" case_mysql_queries
                fi
                ;;
        esac
    done
    print_summary "Linux non-TLS output E2E"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    trap 'status=$?; common_config_cleanup "$status"; exit $?' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    main "$@"
fi
