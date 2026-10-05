#!/usr/bin/env bash
# Shared, host-side assertions and result reporting for eCapture E2E tests.

if [[ -n "${ECAPTURE_E2E_TESTLIB_LOADED:-}" ]]; then
    return 0
fi
readonly ECAPTURE_E2E_TESTLIB_LOADED=1

readonly E2E_RED='\033[0;31m'
readonly E2E_GREEN='\033[0;32m'
readonly E2E_YELLOW='\033[1;33m'
readonly E2E_BLUE='\033[0;34m'
readonly E2E_NC='\033[0m'

log_info() { printf "%b[INFO]%b %s\n" "$E2E_BLUE" "$E2E_NC" "$*"; }
log_success() { printf "%b[PASS]%b %s\n" "$E2E_GREEN" "$E2E_NC" "$*"; }
log_warn() { printf "%b[WARN]%b %s\n" "$E2E_YELLOW" "$E2E_NC" "$*"; }
log_error() { printf "%b[FAIL]%b %s\n" "$E2E_RED" "$E2E_NC" "$*" >&2; }

E2E_TOTAL=0
E2E_PASSED=0
E2E_FAILED=0
E2E_FAILED_CASES=()

run_case() {
    local name="$1"
    shift

    E2E_TOTAL=$((E2E_TOTAL + 1))
    log_info "CASE $name"
    if "$@"; then
        E2E_PASSED=$((E2E_PASSED + 1))
        log_success "$name"
        return 0
    fi

    E2E_FAILED=$((E2E_FAILED + 1))
    E2E_FAILED_CASES+=("$name")
    log_error "$name"
    return 0
}

print_summary() {
    local suite="$1"
    log_info "$suite: $E2E_PASSED/$E2E_TOTAL cases passed"
    if ((E2E_FAILED > 0)); then
        log_error "Failed cases: ${E2E_FAILED_CASES[*]}"
        return 1
    fi
    return 0
}

require_command() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        log_error "Required command not found: $command_name"
        return 1
    fi
}

assert_file_nonempty() {
    local file="$1"
    local description="${2:-file}"
    if [[ ! -s "$file" ]]; then
        log_error "$description is missing or empty: $file"
        return 1
    fi
}

assert_file_contains() {
    local file="$1"
    local literal="$2"
    local description="${3:-expected text}"
    assert_file_nonempty "$file" "$description" || return 1
    if ! grep -Fq -- "$literal" "$file"; then
        log_error "$description not found in $file: $literal"
        tail -n 80 "$file" >&2 || true
        return 1
    fi
}

assert_no_capture_errors() {
    local log_file="$1"
    assert_file_nonempty "$log_file" "eCapture log" || return 1

    local error_pattern='(^|[[:space:]])FTL([[:space:]]|$)|panic:|Failed to decode event|lost [1-9][0-9]* samples|failed to (load|attach|start)'
    if grep -Eiq "$error_pattern" "$log_file"; then
        log_error "eCapture reported a fatal, decode, loss, load, attach, or start error"
        grep -Ein "$error_pattern" "$log_file" | tail -n 40 >&2 || true
        return 1
    fi
}

assert_keylog() {
    local keylog_file="$1"
    assert_file_nonempty "$keylog_file" "NSS keylog" || return 1

    local keylog_pattern='^(CLIENT_RANDOM|CLIENT_EARLY_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_[0-9]+|SERVER_TRAFFIC_SECRET_[0-9]+|EXPORTER_SECRET) [0-9A-Fa-f]{64} [0-9A-Fa-f]{32,}$'
    if ! grep -Eq "$keylog_pattern" "$keylog_file"; then
        log_error "No valid NSS keylog line found in $keylog_file"
        head -n 20 "$keylog_file" >&2 || true
        return 1
    fi

    if grep -Evq "^#|^[[:space:]]*$|$keylog_pattern" "$keylog_file"; then
        log_error "Malformed line found in NSS keylog: $keylog_file"
        grep -Env "^#|^[[:space:]]*$|$keylog_pattern" "$keylog_file" | head -n 20 >&2 || true
        return 1
    fi
}

mode_enabled() {
    local requested="$1"
    local mode
    for mode in ${E2E_MODES:-text keylog pcapng}; do
        if [[ "$mode" == "$requested" ]]; then
            return 0
        fi
    done
    return 1
}

validate_modes() {
    local mode
    for mode in ${E2E_MODES:-text keylog pcapng}; do
        case "$mode" in
            text|keylog|pcapng) ;;
            *)
                log_error "Unsupported E2E mode '$mode'; expected text, keylog, or pcapng"
                return 1
                ;;
        esac
    done
}
