#!/usr/bin/env bash
# Linux-only E2E harness: Ubuntu 22.04+ or Debian 13+, including LoongArch64.

set -euo pipefail

LINUX_E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$LINUX_E2E_DIR/.." && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../.." && pwd)"

# shellcheck source=test/e2e/lib/testlib.sh
source "$E2E_DIR/lib/testlib.sh"
# shellcheck source=test/e2e/linux/platform.sh
source "$LINUX_E2E_DIR/platform.sh"

ECAPTURE_BINARY="${ECAPTURE_BINARY:-$ROOT_DIR/bin/ecapture}"
CAPTURE_PID=""
TLS_SERVER_PID=""
WORK_DIR=""
TLS_SERVER_PORT=""
TLS_SERVER_URL=""
HTTP_REASSEMBLY_SERVER=""
HTTP_REASSEMBLY_PID=""
HTTP_REASSEMBLY_PORT=""
HTTP_REASSEMBLY_URL=""
HTTP3_PID=""
E2E_TOKEN=""
PCAPNG_CHECK=""
OUTPUT_RECEIVER_PID=""
OUTPUT_RECEIVER_URI=""
OUTPUT_RECEIVER_FLAG="output"
OUTPUT_RECEIVER_MODE=""
OUTPUT_RECEIVER_FILE=""
OUTPUT_RECEIVER_FORMAT="text"
CAPTURE_FORMAT="text"
CAPTURE_SENSITIVE="true"
CAPTURE_LOG_FILE=""
CAPTURE_OUTPUTS=()
CAPTURE_CONSOLES=()

check_linux_environment() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "E2E execution requires Linux; current OS is $(uname -s)"
        return 1
    fi

    # Keep an explicit distribution/architecture matrix. Platform checks must
    # precede helper compilation and all eBPF work.
    local ID="" VERSION_ID=""
    # shellcheck disable=SC1091
    source /etc/os-release
    check_linux_platform "$(uname -s)" "$ID" "$VERSION_ID" \
        "$(uname -m)" "$(uname -r)" "$EUID" || return 1

    # The text suite also decrypts its pcapng source, so it needs tshark too.
    local tool
    for tool in go timeout cc curl tshark; do
        require_command "$tool" || return 1
    done
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
    go build -o "$helper_dir/tls_server" "$E2E_DIR/fixtures/tls_server/main.go"
    go build -o "$helper_dir/http_reassembly_server" "$E2E_DIR/fixtures/http_reassembly_server/main.go"
    HTTP_REASSEMBLY_SERVER="$helper_dir/http_reassembly_server"
    go build -o "$helper_dir/pcapng_check" "$E2E_DIR/fixtures/pcapng_check/main.go"
    go build -o "$helper_dir/output_receiver" "$E2E_DIR/fixtures/output_receiver/main.go"
    go build -o "$helper_dir/ecaptureq_assert" "$E2E_DIR/fixtures/ecaptureq_assert/main.go"
    PCAPNG_CHECK="$helper_dir/pcapng_check"
}

# Receivers retain the wire JSON and expose validated, decoded event projections.
start_output_receiver() {
    local mode="$1" output_file="$2" format="${3:-text}"
    OUTPUT_RECEIVER_MODE="$mode"
    OUTPUT_RECEIVER_FILE="$output_file"
    OUTPUT_RECEIVER_FORMAT="$format"
    OUTPUT_RECEIVER_FLAG="output"
    local ready_file="$output_file.ready" receiver_log="$output_file.receiver.log"
    if [[ "$output_file" != "$WORK_DIR/"* ]]; then
        log_error "Receiver output must belong to this suite's artifacts"
        return 1
    fi
    rm -f -- "$ready_file" "$output_file" "$output_file.runtime.log"
    if [[ "$mode" == ws ]]; then
        # Consumed by the module suites that source this helper.
        # shellcheck disable=SC2034
        OUTPUT_RECEIVER_FLAG="stream-listen"
        OUTPUT_RECEIVER_URI="ws://127.0.0.1:$((30000 + RANDOM % 20000))/events"
        # Connection is established after the capture listener starts.
        return 0
    fi
    "$WORK_DIR/helpers/output_receiver" --mode tcp --listen 127.0.0.1:0 \
        --ready-file "$ready_file" --output "$output_file.events.jsonl" >"$receiver_log" 2>&1 &
    OUTPUT_RECEIVER_PID=$!
    wait_for_receiver_ready "$ready_file" "$OUTPUT_RECEIVER_PID" || return 1
    OUTPUT_RECEIVER_URI="$(tr -d '\r\n' <"$ready_file")"
}

wait_for_receiver_ready() {
    local ready_file="$1" receiver_pid="$2" attempt
    for attempt in $(seq 1 100); do
        [[ -s "$ready_file" ]] && return 0
        kill -0 "$receiver_pid" 2>/dev/null || break
        sleep 0.1
    done
    log_error "Receiver did not become ready: $ready_file"
    return 1
}

connect_stream_receiver() {
    [[ "$OUTPUT_RECEIVER_MODE" == ws ]] || return 0
    local ready_file="$OUTPUT_RECEIVER_FILE.ready"
    "$WORK_DIR/helpers/ecaptureq_assert" --server "$OUTPUT_RECEIVER_URI" \
        --format "$OUTPUT_RECEIVER_FORMAT" --sensitive="$CAPTURE_SENSITIVE" --extract-events "$OUTPUT_RECEIVER_FILE" \
        --extract-logs "$OUTPUT_RECEIVER_FILE.runtime.log" --ready-file "$ready_file" \
        --drain >"$OUTPUT_RECEIVER_FILE.receiver.log" 2>&1 &
    OUTPUT_RECEIVER_PID=$!
    wait_for_receiver_ready "$ready_file" "$OUTPUT_RECEIVER_PID"
}

stop_output_receiver() {
    [[ -n "$OUTPUT_RECEIVER_PID" ]] || return 0
    local attempt status=0
    for attempt in $(seq 1 100); do
        kill -0 "$OUTPUT_RECEIVER_PID" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$OUTPUT_RECEIVER_PID" 2>/dev/null; then
        kill -TERM "$OUTPUT_RECEIVER_PID" 2>/dev/null || true
        status=1
    fi
    wait "$OUTPUT_RECEIVER_PID" || status=$?
    if ((status == 0)) && [[ "$OUTPUT_RECEIVER_MODE" == tcp ]]; then
        "$WORK_DIR/helpers/ecaptureq_assert" --json-input "$OUTPUT_RECEIVER_FILE.events.jsonl" \
            --format "$OUTPUT_RECEIVER_FORMAT" --sensitive="$CAPTURE_SENSITIVE" --extract-events "$OUTPUT_RECEIVER_FILE" \
            --extract-logs "$OUTPUT_RECEIVER_FILE.runtime.log" \
            >"$OUTPUT_RECEIVER_FILE.validation.log" 2>&1 || status=$?
    fi
    OUTPUT_RECEIVER_PID=""
    OUTPUT_RECEIVER_URI=""
    OUTPUT_RECEIVER_MODE=""
    if ((status != 0)); then
        log_error "Output receiver validation failed with status $status"
        return 1
    fi
}

# Projections are test artifacts; output destinations themselves always use the
# new CLI. Every raw JSON record is checked with the same v2 schema as WebSocket.
prepare_capture_outputs() {
    CAPTURE_OUTPUTS=()
    CAPTURE_CONSOLES=()
    CAPTURE_FORMAT=text
    CAPTURE_SENSITIVE=true
    local previous="" argument
    for argument in "$@"; do
        case "$previous" in
            --model|--mode) CAPTURE_FORMAT="$argument" ;;
            --text-source) [[ "$argument" == hook ]] && CAPTURE_SENSITIVE=false ;;
            --output) [[ "$argument" == *.jsonl ]] && CAPTURE_OUTPUTS+=("$argument") ;;
        esac
        previous="$argument"
    done
    local path
    for path in "${CAPTURE_OUTPUTS[@]}"; do
        # Some cases intentionally reuse their output contract. A prior
        # generation's startup marker must not make the next probe look ready.
        # Production file append behavior remains unchanged.
        if [[ "$path" != "$WORK_DIR/"* ]]; then
            log_error "Refusing to reset an output outside this suite's artifacts"
            return 1
        fi
        : >"$path"
        case "$path" in
            *.events.jsonl) rm -f -- "${path%.events.jsonl}" ;;
            *.logs.jsonl) rm -f -- "${path%.logs.jsonl}" ;;
        esac
    done
}

refresh_projection() {
    local target="$1" raw="" option=""
    if [[ -f "$target.events.jsonl" ]]; then
        raw="$target.events.jsonl"; option=--extract-events
    elif [[ -f "$target.logs.jsonl" ]]; then
        raw="$target.logs.jsonl"; option=--extract-logs
    else
        return 0
    fi
    local extra=()
    if [[ "$option" == --extract-logs && "$CAPTURE_FORMAT" != text ]]; then
        extra+=(--logs-only)
    fi
    if ! "$WORK_DIR/helpers/ecaptureq_assert" --json-input "$raw" --format "$CAPTURE_FORMAT" --sensitive="$CAPTURE_SENSITIVE" \
        "$option" "$target" "${extra[@]}" >"$raw.validation.log" 2>&1; then
        log_error "Output record validation failed: $raw"
        grep '^ECAPTUREQ_ASSERTION: ' "$raw.validation.log" >&2 || true
        return 1
    fi
}

refresh_capture_outputs() {
    local path
    for path in "${CAPTURE_OUTPUTS[@]}"; do
        path="${path%.events.jsonl}"; path="${path%.logs.jsonl}"
        refresh_projection "$path" || return 1
    done
    for path in "${CAPTURE_CONSOLES[@]}"; do
        assert_file_nonempty "$path" "labeled terminal output" || return 1
        if grep -Eqv '^\[log_type=(log|event) ' "$path"; then
            log_error "Terminal output contains an unlabeled physical line"
            return 1
        fi
        # Each physical line is labeled, including multiline payloads.
        grep '^\[log_type=event ' "$path" | sed 's/^\[[^]]*\] //' >"${path%.console}" || true
    done
}

# Refresh snapshots while a producer is live. A partially written final JSON
# line is retried; final validation after shutdown never tolerates truncation.
wait_for_file_contains() {
    local file="$1" literal="$2" description="$3" attempt
    for ((attempt = 0; attempt < 100; attempt++)); do
        refresh_projection "$file" >/dev/null 2>&1 || true
        if [[ -f "$file" ]] && grep -Fq -- "$literal" "$file"; then return 0; fi
        sleep 0.05
    done
    log_error "$description did not arrive before capture shutdown"
    return 1
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

start_http_reassembly_fixture() {
    local enable_h2="$1"  # "true" or "false"
    local ready_file="$WORK_DIR/http-reassembly-server.addr"
    local server_log="$WORK_DIR/http-reassembly-server.log"
    rm -f -- "$ready_file"
    "$HTTP_REASSEMBLY_SERVER" \
        --listen 127.0.0.1:0 \
        --ready-file "$ready_file" \
        --token "$E2E_TOKEN" \
        --h2="$enable_h2" >"$server_log" 2>&1 &
    HTTP_REASSEMBLY_PID=$!

    local attempt
    for attempt in $(seq 1 50); do
        if [[ -s "$ready_file" ]]; then
            local address
            address="$(tr -d '\r\n' <"$ready_file")"
            HTTP_REASSEMBLY_PORT="${address##*:}"
            HTTP_REASSEMBLY_URL="https://127.0.0.1:$HTTP_REASSEMBLY_PORT"
            log_info "Local HTTP reassembly fixture: $HTTP_REASSEMBLY_URL (h2=$enable_h2)"
            return 0
        fi
        if ! kill -0 "$HTTP_REASSEMBLY_PID" 2>/dev/null; then
            log_error "HTTP reassembly fixture exited before becoming ready"
            cat "$server_log" >&2 || true
            return 1
        fi
        sleep 0.1
    done

    log_error "Timed out waiting for HTTP reassembly fixture"
    return 1
}

stop_http_reassembly_fixture() {
    if [[ -n "$HTTP_REASSEMBLY_PID" ]] && kill -0 "$HTTP_REASSEMBLY_PID" 2>/dev/null; then
        kill -TERM "$HTTP_REASSEMBLY_PID" 2>/dev/null || true
        wait "$HTTP_REASSEMBLY_PID" 2>/dev/null || true
    fi
    HTTP_REASSEMBLY_PID=""
    HTTP_REASSEMBLY_PORT=""
    HTTP_REASSEMBLY_URL=""
}

start_capture() {
    local log_file="$1"
    shift

    prepare_capture_outputs "$@" || return 1
    CAPTURE_LOG_FILE="$log_file"
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
        if grep -Eiq 'probe started successfully' "$log_file" "${CAPTURE_OUTPUTS[@]}" 2>/dev/null; then
            connect_stream_receiver
            return $?
        fi
        sleep 0.2
    done

    log_error "Capture startup marker was not observed"
    return 1
}

start_capture_split() {
    local stdout_file="$1"
    local stderr_file="$2"
    shift 2

    prepare_capture_outputs "$@" || return 1
    CAPTURE_LOG_FILE="$stderr_file"
    [[ "$stdout_file" == *.console ]] && CAPTURE_CONSOLES+=("$stdout_file")
    if [[ "$stderr_file" == *.console ]]; then
        CAPTURE_CONSOLES+=("$stderr_file")
        CAPTURE_LOG_FILE="$stdout_file"
    fi
    : >"$stdout_file"
    : >"$stderr_file"
    log_info "Starting with split stdout/stderr: $ECAPTURE_BINARY $*"
    "$ECAPTURE_BINARY" "$@" >"$stdout_file" 2>"$stderr_file" &
    CAPTURE_PID=$!

    local attempt
    for attempt in $(seq 1 30); do
        if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            wait "$CAPTURE_PID" 2>/dev/null || true
            log_error "eCapture exited during initialization"
            tail -n 100 "$stderr_file" >&2 || true
            CAPTURE_PID=""
            return 1
        fi
        if grep -Eiq 'probe started successfully' "$stderr_file" "$stdout_file" "${CAPTURE_OUTPUTS[@]}" 2>/dev/null; then
            connect_stream_receiver
            return $?
        fi
        sleep 0.2
    done
    log_error "Capture startup marker was not observed"
    return 1
}

stop_capture() {
    local signal="${1:-INT}" forced=0
    if [[ -z "$CAPTURE_PID" ]]; then
        return 0
    fi

    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill "-$signal" "$CAPTURE_PID" 2>/dev/null || true
        local attempt
        for attempt in $(seq 1 30); do
            if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
    fi
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        forced=1
        kill -TERM "$CAPTURE_PID" 2>/dev/null || true
        sleep 0.5
    fi
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -KILL "$CAPTURE_PID" 2>/dev/null || true
    fi
    local status=0
    wait "$CAPTURE_PID" 2>/dev/null || status=$?
    CAPTURE_PID=""
    if ((status != 0 || forced != 0)); then
        log_error "Capture did not stop cleanly after SIG$signal (exit=$status, forced=$forced)"
        return 1
    fi
    refresh_capture_outputs || return 1
    if ((${#CAPTURE_OUTPUTS[@]} > 0)); then
        # Explicit output replaces terminal logging. Preserve the untouched stdio
        # artifact and collect a validated runtime projection for fatal checks.
        local path="${CAPTURE_OUTPUTS[0]}"
        "$WORK_DIR/helpers/ecaptureq_assert" --json-input "$path" --format "$CAPTURE_FORMAT" --sensitive="$CAPTURE_SENSITIVE" \
            --extract-logs "$CAPTURE_LOG_FILE.output.log" >"$CAPTURE_LOG_FILE.validation.log" 2>&1 || return 1
        cp -- "$CAPTURE_LOG_FILE" "$CAPTURE_LOG_FILE.stdio"
        cat "$CAPTURE_LOG_FILE.output.log" >>"$CAPTURE_LOG_FILE"
    fi
}

post_config_update() {
    local endpoint="$1"
    local request_body="$2"
    local response_file="$3"
    local expect_success="$4"
    local status

    status="$(curl --silent --show-error --output "$response_file" \
        --write-out '%{http_code}' \
        --header 'Content-Type: application/json' \
        --request POST \
        --data-binary "@$request_body" \
        "$endpoint")" || {
        log_error "Configuration request failed before receiving an HTTP response"
        return 1
    }

    if [[ "$expect_success" == "1" ]]; then
        if [[ ! "$status" =~ ^2 ]]; then
            log_error "Configuration update returned HTTP $status"
            cat "$response_file" >&2 || true
            return 1
        fi
        return 0
    fi
    if [[ "$status" =~ ^2 ]]; then
        log_error "Invalid configuration update unexpectedly returned HTTP $status"
        return 1
    fi
}

assert_pcapng() {
    local pcap_file="$1"
    local min_packets="${2:-1}"
    assert_file_nonempty "$pcap_file" "pcapng capture" || return 1
    "$PCAPNG_CHECK" --require-dsb --min-packets "$min_packets" "$pcap_file"
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
    stop_output_receiver || true
    stop_packet_capture || true
    stop_http_reassembly_fixture || true
    if [[ -n "$HTTP3_PID" ]]; then
        kill -TERM "$HTTP3_PID" 2>/dev/null || true
        wait "$HTTP3_PID" 2>/dev/null || true
    fi
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
