#!/usr/bin/env bash
# Linux-only OpenSSL/eBPF benchmark modeled on GitHub issue #990.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

ECAPTURE_BINARY="${ECAPTURE_BINARY:-$ROOT_DIR/bin/ecapture}"
BENCH_REQUESTS="${BENCH_REQUESTS:-160}"
BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-1}"
BENCH_PAYLOAD_BYTES="${BENCH_PAYLOAD_BYTES:-98304}"
BENCH_DELAY_MS="${BENCH_DELAY_MS:-10}"
BENCH_RUNS="${BENCH_RUNS:-3}"
BENCH_MAP_PAGES="${BENCH_MAP_PAGES:-8192}"
BENCH_TLS_VERSION="${BENCH_TLS_VERSION:-tls13}"
BENCH_FAIL_ON_LOSS="${BENCH_FAIL_ON_LOSS:-0}"
BENCH_ARTIFACT_ROOT="${BENCH_ARTIFACT_ROOT:-/tmp/ecapture-benchmark}"

CAPTURE_PID=""
MONITOR_PID=""
SERVER_PID=""
WORK_DIR=""
CLIENT_BINARY=""
SERVER_BINARY=""
SERVER_PORT=""
OPENSSL_LIB=""
INFRA_FAILURES=0
LOSS_FAILURES=0

log() { printf '[benchmark] %s\n' "$*"; }
fail() { printf '[benchmark] ERROR: %s\n' "$*" >&2; exit 1; }

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

validate_positive_integer() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || fail "$name must be a positive integer (got: $value)"
}

stop_monitor() {
    if [[ -n "$MONITOR_PID" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
        MONITOR_PID=""
    fi
}

stop_capture() {
    stop_monitor
    if [[ -z "$CAPTURE_PID" ]]; then
        return 0
    fi
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        local attempt
        for attempt in $(seq 1 50); do
            kill -0 "$CAPTURE_PID" 2>/dev/null || break
            sleep 0.1
        done
    fi
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -TERM "$CAPTURE_PID" 2>/dev/null || true
    fi
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""
}

cleanup() {
    stop_capture
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$WORK_DIR" ]]; then
        log "artifacts preserved in $WORK_DIR"
        log "warning: captured plaintext in this directory may contain sensitive data"
    fi
}

check_environment() {
    [[ "$(uname -s)" == "Linux" ]] || fail "this benchmark requires Linux"
    ((EUID == 0)) || fail "this benchmark requires root; run it with sudo"
    local arch major minor required_major required_minor
    arch="$(uname -m)"
    IFS=. read -r major minor _ <<<"$(uname -r)"
    case "$arch" in
        x86_64) required_major=4; required_minor=18 ;;
        aarch64|arm64) required_major=5; required_minor=5 ;;
        *) fail "unsupported architecture: $(uname -m)" ;;
    esac
    if ((major < required_major || (major == required_major && minor < required_minor))); then
        fail "kernel $(uname -r) is too old for $arch; need ${required_major}.${required_minor}+"
    fi
    require_command awk
    require_command cc
    require_command find
    require_command free
    require_command getconf
    require_command git
    require_command go
    require_command ldd
    require_command lscpu
    require_command openssl
    require_command ps
    require_command sort
    require_command timeout
    [[ -x "$ECAPTURE_BINARY" ]] || fail "eCapture binary not found: $ECAPTURE_BINARY (build with make all first)"

    validate_positive_integer BENCH_REQUESTS "$BENCH_REQUESTS"
    validate_positive_integer BENCH_CONCURRENCY "$BENCH_CONCURRENCY"
    validate_positive_integer BENCH_PAYLOAD_BYTES "$BENCH_PAYLOAD_BYTES"
    validate_positive_integer BENCH_RUNS "$BENCH_RUNS"
    validate_positive_integer BENCH_MAP_PAGES "$BENCH_MAP_PAGES"
    [[ "$BENCH_DELAY_MS" =~ ^[0-9]+([.][0-9]+)?$ ]] || fail "BENCH_DELAY_MS must be non-negative"
    [[ "$BENCH_TLS_VERSION" == "tls12" || "$BENCH_TLS_VERSION" == "tls13" ]] || \
        fail "BENCH_TLS_VERSION must be tls12 or tls13"
    [[ "$BENCH_FAIL_ON_LOSS" == "0" || "$BENCH_FAIL_ON_LOSS" == "1" ]] || \
        fail "BENCH_FAIL_ON_LOSS must be 0 or 1"
}

build_fixtures() {
    mkdir -p "$BENCH_ARTIFACT_ROOT"
    WORK_DIR="$(mktemp -d "$BENCH_ARTIFACT_ROOT/tls.XXXXXX")"
    chmod 700 "$WORK_DIR"
    CLIENT_BINARY="$WORK_DIR/openssl_bench_client"
    SERVER_BINARY="$WORK_DIR/tls_bench_server"

    cc -O2 -Wall -Wextra -Werror -o "$CLIENT_BINARY" \
        "$SCRIPT_DIR/fixtures/c/openssl_client.c" -lssl -lcrypto
    go build -o "$SERVER_BINARY" "$SCRIPT_DIR/fixtures/server/main.go"

    OPENSSL_LIB="$(ldd "$CLIENT_BINARY" | awk '$1 ~ /^libssl[.]so/ {print $3; exit}')"
    [[ -n "$OPENSSL_LIB" && -f "$OPENSSL_LIB" ]] || fail "could not resolve libssl used by benchmark client"
}

write_environment() {
    {
        printf 'date: '
        date -Iseconds
        printf 'repository_commit: '
        git -C "$ROOT_DIR" rev-parse HEAD
        printf 'benchmark_config: requests=%s concurrency=%s payload_bytes=%s delay_ms=%s runs=%s map_pages=%s tls=%s\n' \
            "$BENCH_REQUESTS" "$BENCH_CONCURRENCY" "$BENCH_PAYLOAD_BYTES" "$BENCH_DELAY_MS" \
            "$BENCH_RUNS" "$BENCH_MAP_PAGES" "$BENCH_TLS_VERSION"
        printf 'client_libssl: %s\n' "$OPENSSL_LIB"
        printf 'page_size_bytes: '
        getconf PAGESIZE
        uname -a
        cat /etc/os-release
        lscpu
        free -h
        openssl version -a
        go version
        cc --version
        "$ECAPTURE_BINARY" --version || true
        ldd "$CLIENT_BINARY"
    } >"$WORK_DIR/environment.txt" 2>&1
}

start_server() {
    local ready_file="$WORK_DIR/server.addr"
    "$SERVER_BINARY" --listen 127.0.0.1:0 --ready-file "$ready_file" \
        >"$WORK_DIR/server.log" 2>&1 &
    SERVER_PID=$!

    local attempt address
    for attempt in $(seq 1 100); do
        if [[ -s "$ready_file" ]]; then
            address="$(tr -d '\r\n' <"$ready_file")"
            SERVER_PORT="${address##*:}"
            return 0
        fi
        kill -0 "$SERVER_PID" 2>/dev/null || fail "TLS fixture exited before becoming ready"
        sleep 0.05
    done
    fail "timed out waiting for TLS fixture"
}

monitor_capture() {
    local sample_file="$1"
    : >"$sample_file"
    while kill -0 "$CAPTURE_PID" 2>/dev/null; do
        ps -p "$CAPTURE_PID" -o %cpu= -o rss= >>"$sample_file" 2>/dev/null || true
        sleep 0.2
    done
}

start_capture() {
    local capture_log="$1"
    local event_log="$2"
    local sample_file="$3"
    : >"$capture_log"
    : >"$event_log"

    "$ECAPTURE_BINARY" tls \
        --libssl "$OPENSSL_LIB" \
        --model text \
        --mapsize "$BENCH_MAP_PAGES" \
        --eventaddr "$event_log" >"$capture_log" 2>&1 &
    CAPTURE_PID=$!

    local attempt
    for attempt in $(seq 1 100); do
        if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            tail -n 100 "$capture_log" >&2 || true
            fail "eCapture exited during initialization"
        fi
        if grep -Fqi 'probe started successfully' "$capture_log"; then
            monitor_capture "$sample_file" &
            MONITOR_PID=$!
            return 0
        fi
        sleep 0.1
    done
    tail -n 100 "$capture_log" >&2 || true
    fail "timed out waiting for eCapture to start"
}

wait_for_batch() {
    local -n batch_pids_ref=$1
    local pid
    for pid in "${batch_pids_ref[@]}"; do
        if ! wait "$pid"; then
            INFRA_FAILURES=$((INFRA_FAILURES + 1))
        fi
    done
    batch_pids_ref=()
}

count_unique_markers() {
    local event_log="$1"
    local marker_pattern="$2"
    if [[ ! -s "$event_log" ]]; then
        printf '0\n'
        return 0
    fi
    { grep -aoE "$marker_pattern" "$event_log" || true; } | sort -u | awk 'END {print NR}'
}

sum_lost_samples() {
    local capture_log="$1"
    if [[ ! -s "$capture_log" ]]; then
        printf '0\n'
        return 0
    fi
    { grep -aoE 'lost_samples[=:][[:space:]]*[0-9]+' "$capture_log" || true; } |
        awk -F'[=:]' '{gsub(/[[:space:]]/, "", $2); sum += $2} END {print sum + 0}'
}

run_load() {
    local phase="$1"
    local run="$2"
    local run_dir="$WORK_DIR/${run}-${phase}"
    local client_dir="$run_dir/clients"
    local capture_log="$run_dir/ecapture.log"
    local event_log="$run_dir/events.log"
    local sample_file="$run_dir/ecapture-process.tsv"
    local prefix="ECAPTURE_BENCH_${run}_${phase^^}_$$_"
    local delay_seconds
    delay_seconds="$(awk -v delay="$BENCH_DELAY_MS" 'BEGIN {printf "%.6f", delay / 1000}')"

    mkdir -p "$client_dir"
    if [[ "$phase" == "capture" ]]; then
        start_capture "$capture_log" "$event_log" "$sample_file"
    fi

    local started_ns finished_ns request token result_file error_file
    local -a batch_pids=()
    started_ns="$(date +%s%N)"
    for ((request = 1; request <= BENCH_REQUESTS; request++)); do
        token="$(printf '%sREQ_%06d' "$prefix" "$request")"
        result_file="$(printf '%s/%06d.duration' "$client_dir" "$request")"
        error_file="$(printf '%s/%06d.stderr' "$client_dir" "$request")"
        timeout 30 "$CLIENT_BINARY" 127.0.0.1 "$SERVER_PORT" "$token" \
            "$BENCH_PAYLOAD_BYTES" "$BENCH_TLS_VERSION" >"$result_file" 2>"$error_file" &
        batch_pids+=("$!")

        if [[ "$BENCH_DELAY_MS" != "0" ]]; then
            sleep "$delay_seconds"
        fi
        if ((${#batch_pids[@]} == BENCH_CONCURRENCY || request == BENCH_REQUESTS)); then
            wait_for_batch batch_pids
        fi
    done
    finished_ns="$(date +%s%N)"

    if [[ "$phase" == "capture" ]]; then
        sleep 2
        if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            log "eCapture exited before capture run $run completed"
            INFRA_FAILURES=$((INFRA_FAILURES + 1))
        fi
        stop_capture
    fi

    local durations_file="$run_dir/durations-us.txt"
    find "$client_dir" -type f -name '*.duration' -size +0c -exec awk 'NF == 1 && $1 ~ /^[0-9]+$/ {print $1}' {} + \
        | sort -n >"$durations_file"

    local successes wall_ms requests_per_second p50 p95 p99
    successes="$(awk 'END {print NR}' "$durations_file")"
    wall_ms="$(((finished_ns - started_ns) / 1000000))"
    requests_per_second="$(awk -v count="$successes" -v ms="$wall_ms" \
        'BEGIN {if (ms == 0) print "0.00"; else printf "%.2f", count * 1000 / ms}')"
    read -r p50 p95 p99 < <(awk '
        {values[NR] = $1}
        END {
            if (NR == 0) {print "0 0 0"; exit}
            p50 = int((NR * 50 + 99) / 100)
            p95 = int((NR * 95 + 99) / 100)
            p99 = int((NR * 99 + 99) / 100)
            print values[p50], values[p95], values[p99]
        }' "$durations_file")

    local captured_requests="-" captured_responses="-" loss_pct="-" lost_samples="-"
    local cpu_avg="-" rss_max="-" capture_errors="-"
    if [[ "$phase" == "capture" ]]; then
        captured_requests="$(count_unique_markers "$event_log" "${prefix}REQ_[0-9]{6}")"
        captured_responses="$(count_unique_markers "$event_log" "${prefix}RESP_[0-9]{6}")"
        loss_pct="$(awk -v expected="$((BENCH_REQUESTS * 2))" \
            -v observed="$((captured_requests + captured_responses))" \
            'BEGIN {missing = expected - observed; if (missing < 0) missing = 0; printf "%.4f", missing * 100 / expected}')"
        lost_samples="$(sum_lost_samples "$capture_log")"
        read -r cpu_avg rss_max < <(awk '
            NF >= 2 {cpu += $1; count++; if ($2 > rss) rss = $2}
            END {if (count == 0) print "0.00 0"; else printf "%.2f %d\n", cpu / count, rss}
        ' "$sample_file")
        capture_errors="$({ grep -Eic '(^|[[:space:]])FTL([[:space:]]|$)|panic:|Failed to decode event|failed to (load|attach|start)' \
            "$capture_log" || true; })"
        if ((capture_errors > 0)); then
            log "capture run $run reported $capture_errors fatal/decode/start errors"
            INFRA_FAILURES=$((INFRA_FAILURES + 1))
        fi
        if [[ "$BENCH_FAIL_ON_LOSS" == "1" ]] && \
           ((captured_requests != BENCH_REQUESTS || captured_responses != BENCH_REQUESTS || lost_samples != 0)); then
            LOSS_FAILURES=$((LOSS_FAILURES + 1))
        fi
    fi

    if ((successes != BENCH_REQUESTS)); then
        log "$phase run $run completed only $successes/$BENCH_REQUESTS requests"
    fi
    printf '%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$phase" "$run" "$BENCH_REQUESTS" "$successes" "$wall_ms" "$requests_per_second" \
        "$p50" "$p95" "$p99" "$BENCH_REQUESTS" "$captured_requests" "$BENCH_REQUESTS" \
        "$captured_responses" "$loss_pct" "$lost_samples" "$capture_errors" "$cpu_avg" "$rss_max" \
        >>"$WORK_DIR/summary.tsv"
}

write_comparison() {
    awk -F '\t' 'BEGIN {
        OFS = "\t"
        print "run", "throughput_delta_pct", "p99_delta_pct", "marker_loss_pct", "perf_lost_samples", "capture_errors", "ecapture_cpu_avg_pct", "ecapture_rss_max_kb"
    }
    NR == 1 {next}
    $1 == "baseline" {base_rps[$2] = $6; base_p99[$2] = $9; next}
    $1 == "capture" {
        rps_delta = base_rps[$2] == 0 ? 0 : ($6 - base_rps[$2]) * 100 / base_rps[$2]
        p99_delta = base_p99[$2] == 0 ? 0 : ($9 - base_p99[$2]) * 100 / base_p99[$2]
        printf "%d\t%.2f\t%.2f\t%s\t%s\t%s\t%s\t%s\n", $2, rps_delta, p99_delta, $14, $15, $16, $17, $18
    }' "$WORK_DIR/summary.tsv" >"$WORK_DIR/comparison.tsv"
}

main() {
    check_environment
    umask 077
    trap cleanup EXIT
    trap 'exit 130' INT TERM
    build_fixtures
    write_environment
    start_server

    {
        printf 'phase\trun\trequests\tsuccesses\twall_ms\trequests_per_sec\tp50_us\tp95_us\tp99_us\t'
        printf 'expected_request_markers\tcaptured_request_markers\texpected_response_markers\t'
        printf 'captured_response_markers\tmarker_loss_pct\tperf_lost_samples\tcapture_errors\t'
        printf 'ecapture_cpu_avg_pct\tecapture_rss_max_kb\n'
    } >"$WORK_DIR/summary.tsv"

    log "OpenSSL library: $OPENSSL_LIB"
    log "requests=$BENCH_REQUESTS concurrency=$BENCH_CONCURRENCY payload_bytes=$BENCH_PAYLOAD_BYTES delay_ms=$BENCH_DELAY_MS runs=$BENCH_RUNS map_pages=$BENCH_MAP_PAGES"
    local run
    for ((run = 1; run <= BENCH_RUNS; run++)); do
        log "run $run/$BENCH_RUNS: baseline"
        run_load baseline "$run"
        log "run $run/$BENCH_RUNS: eCapture text mode"
        run_load capture "$run"
    done
    write_comparison

    log "raw summary:"
    awk -F '\t' '{printf "  %s\n", $0}' "$WORK_DIR/summary.tsv"
    log "baseline comparison (negative throughput is overhead; positive p99 is added latency):"
    awk -F '\t' '{printf "  %s\n", $0}' "$WORK_DIR/comparison.tsv"

    if ((INFRA_FAILURES > 0)); then
        fail "$INFRA_FAILURES benchmark client processes failed"
    fi
    if ((LOSS_FAILURES > 0)); then
        fail "$LOSS_FAILURES capture runs exceeded the zero-loss requirement"
    fi
}

main "$@"
