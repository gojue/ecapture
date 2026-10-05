#!/usr/bin/env bash
# Linux-only E2E harness. Supported environment: GitHub Actions Ubuntu 22.04+.

set -euo pipefail

LINUX_E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$LINUX_E2E_DIR/.." && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../.." && pwd)"

# shellcheck source=test/e2e/lib/testlib.sh
source "$E2E_DIR/lib/testlib.sh"

ECAPTURE_BINARY="${ECAPTURE_BINARY:-$ROOT_DIR/bin/ecapture}"
CAPTURE_PID=""
TLS_SERVER_PID=""
WORK_DIR=""
TLS_SERVER_PORT=""
TLS_SERVER_URL=""
E2E_TOKEN=""
PCAPNG_CHECK=""

version_at_least() {
    local actual="$1"
    local required="$2"
    [[ "$(printf '%s\n%s\n' "$required" "$actual" | sort -V | head -n 1)" == "$required" ]]
}

check_linux_environment() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "E2E execution requires Linux; current OS is $(uname -s)"
        return 1
    fi

    # GitHub-hosted images expose the Ubuntu release here. Keeping this strict
    # prevents accidental support claims for untested distributions.
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]] || ! version_at_least "${VERSION_ID:-0}" "22.04"; then
        log_error "Linux E2E supports GitHub Actions Ubuntu 22.04+ only (found ${PRETTY_NAME:-unknown})"
        return 1
    fi
    if ((EUID != 0)); then
        log_error "E2E tests require root; run with sudo"
        return 1
    fi

    local arch major minor required_major required_minor
    arch="$(uname -m)"
    IFS=. read -r major minor _ <<<"$(uname -r)"
    case "$arch" in
        x86_64) required_major=4; required_minor=18 ;;
        aarch64|arm64) required_major=5; required_minor=5 ;;
        *)
            log_error "Unsupported architecture: $arch"
            return 1
            ;;
    esac
    if ((major < required_major || (major == required_major && minor < required_minor))); then
        log_error "Kernel $(uname -r) is too old for $arch"
        return 1
    fi

    require_command go
    require_command timeout
    require_command cc
    [[ -x "$ECAPTURE_BINARY" ]] || {
        log_error "eCapture binary not found: $ECAPTURE_BINARY (build with make all first)"
        return 1
    }
}

create_work_dir() {
    local module="$1"
    local artifact_root="${E2E_ARTIFACT_ROOT:-/tmp/ecapture-e2e}"
    mkdir -p "$artifact_root"
    WORK_DIR="$(mktemp -d "$artifact_root/${module}.XXXXXX")"
    E2E_TOKEN="ECAPTURE_E2E_${module^^}_$$_${RANDOM}"
    log_info "Artifacts: $WORK_DIR"
}

build_host_helpers() {
    local helper_dir="$WORK_DIR/helpers"
    mkdir -p "$helper_dir"
    go build -o "$helper_dir/tls_server" "$E2E_DIR/fixtures/tls_server.go"
    go build -o "$helper_dir/pcapng_check" "$E2E_DIR/fixtures/pcapng_check.go"
    PCAPNG_CHECK="$helper_dir/pcapng_check"
}

start_tls_fixture() {
    local ready_file="$WORK_DIR/tls-server.addr"
    local server_log="$WORK_DIR/tls-server.log"
    "$WORK_DIR/helpers/tls_server" \
        --listen 127.0.0.1:0 \
        --ready-file "$ready_file" \
        --token "$E2E_TOKEN" >"$server_log" 2>&1 &
    TLS_SERVER_PID=$!

    local attempt
    for attempt in $(seq 1 50); do
        if [[ -s "$ready_file" ]]; then
            local address
            address="$(tr -d '\r\n' <"$ready_file")"
            TLS_SERVER_PORT="${address##*:}"
            TLS_SERVER_URL="https://127.0.0.1:$TLS_SERVER_PORT/e2e"
            log_info "Local TLS fixture: $TLS_SERVER_URL"
            return 0
        fi
        if ! kill -0 "$TLS_SERVER_PID" 2>/dev/null; then
            log_error "TLS fixture exited before becoming ready"
            cat "$server_log" >&2 || true
            return 1
        fi
        sleep 0.1
    done

    log_error "Timed out waiting for TLS fixture"
    return 1
}

start_capture() {
    local log_file="$1"
    shift

    : >"$log_file"
    log_info "Starting: $ECAPTURE_BINARY $*"
    "$ECAPTURE_BINARY" "$@" >"$log_file" 2>&1 &
    CAPTURE_PID=$!

    local attempt
    for attempt in $(seq 1 30); do
        if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            wait "$CAPTURE_PID" 2>/dev/null || true
            log_error "eCapture exited during initialization"
            tail -n 100 "$log_file" >&2 || true
            CAPTURE_PID=""
            return 1
        fi
        if grep -Eiq 'probe started successfully' "$log_file"; then
            return 0
        fi
        sleep 0.2
    done

    # Keep a bounded fallback for older binaries that do not emit the marker.
    return 0
}

stop_capture() {
    if [[ -z "$CAPTURE_PID" ]]; then
        return 0
    fi

    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        local attempt
        for attempt in $(seq 1 30); do
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

assert_pcapng() {
    local pcap_file="$1"
    assert_file_nonempty "$pcap_file" "pcapng capture" || return 1
    "$PCAPNG_CHECK" --require-dsb "$pcap_file"
}

resolve_linked_library() {
    local binary="$1"
    local expression="$2"
    local library
    library="$(ldd "$binary" | awk -v pattern="$expression" '$1 ~ pattern {print $3; exit}')"
    if [[ -z "$library" || ! -f "$library" ]]; then
        log_error "Could not resolve $expression from $binary"
        ldd "$binary" >&2 || true
        return 1
    fi
    printf '%s\n' "$library"
}

linux_suite_cleanup() {
    stop_capture || true
    if [[ -n "$TLS_SERVER_PID" ]] && kill -0 "$TLS_SERVER_PID" 2>/dev/null; then
        kill -TERM "$TLS_SERVER_PID" 2>/dev/null || true
        wait "$TLS_SERVER_PID" 2>/dev/null || true
    fi

    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        if [[ "${E2E_KEEP_ARTIFACTS:-0}" == "1" || "$E2E_FAILED" -gt 0 ]]; then
            log_info "Preserving artifacts: $WORK_DIR"
        else
            rm -rf -- "$WORK_DIR"
        fi
    fi
}

setup_linux_suite() {
    local module="$1"
    check_linux_environment
    validate_modes
    create_work_dir "$module"
    trap linux_suite_cleanup EXIT
    trap 'exit 130' INT TERM
    build_host_helpers
    start_tls_fixture
}
