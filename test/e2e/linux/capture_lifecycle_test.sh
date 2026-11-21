#!/usr/bin/env bash
# Exercise capture readiness, termination and diagnostics without eBPF or root.
set -euo pipefail
[[ "$(uname -s)" == Linux ]] || { echo 'Capture lifecycle tests require Linux' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'Capture lifecycle tests require python3' >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for inherited_name in "${!E2E_@}" "${!FAKE_@}"; do
    [[ -z "$inherited_name" ]] || unset "$inherited_name"
done

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

assert_reaped() {
    local pid="$1"
    if kill -0 "$pid" 2>/dev/null; then
        fail "capture process $pid is still alive or unreaped"
    fi
    [[ -z "$CAPTURE_PID" ]] || fail 'CAPTURE_PID was not cleared'
}

assert_safe_diagnostics() {
    local diagnostics="$1"
    grep -Fq 'LIFECYCLE_LOG_SENTINEL' "$diagnostics" || fail 'JSON runtime diagnostic was lost'
    grep -Fq 'TERMINAL_LOG_SENTINEL' "$diagnostics" || fail 'terminal runtime diagnostic was lost'
    grep -Fq 'NESTED_LOG_SENTINEL' "$diagnostics" || fail 'structured runtime diagnostic was lost'
    if grep -Eq 'PRIVATE_SECRET|RVZFTlRfUFJJVkFURV9TRUNSRVQ=|S0VZTE9HX1BSSVZBVEVfU0VDUkVU|event_payload|CLIENT_RANDOM' "$diagnostics"; then
        fail 'capture data or malformed/unclassified output leaked into diagnostics'
    fi
}

case_json_ready() {
    export FAKE_READY_TARGET=json
    start_capture "$WORK_DIR/stdio.log" --output "$WORK_DIR/records.jsonl"
    [[ ! -s "$WORK_DIR/stdio.log" ]] || fail 'JSON-only fixture unexpectedly wrote to stdio'
    local pid="$CAPTURE_PID"
    stop_capture
    assert_reaped "$pid"
}

case_split_ready() {
    export FAKE_READY_TARGET=stderr
    start_capture_split "$WORK_DIR/stdout.log" "$WORK_DIR/stderr.log"
    [[ ! -s "$WORK_DIR/stdout.log" ]] || fail 'split fixture unexpectedly wrote to stdout'
    grep -Fq 'probe started successfully' "$WORK_DIR/stderr.log" || fail 'stderr readiness marker missing'
    local pid="$CAPTURE_PID"
    stop_capture TERM
    assert_reaped "$pid"
}

case_slow_start() {
    # The former six-second readiness budget cannot pass this real delay.
    export FAKE_READY_DELAY=7 FAKE_READY_TARGET=json
    start_capture "$WORK_DIR/stdio.log" --output "$WORK_DIR/records.jsonl"
    local pid="$CAPTURE_PID"
    stop_capture
    assert_reaped "$pid"
}

case_start_timeout() {
    export E2E_CAPTURE_START_TIMEOUT_SECONDS=1 FAKE_READY_TARGET=none FAKE_DIAGNOSTICS=1
    if start_capture "$WORK_DIR/stdio.log" --output "$WORK_DIR/records.jsonl" >"$WORK_DIR/diagnostics.log" 2>&1; then
        fail 'capture without a readiness marker was accepted'
    fi
    grep -Fq 'Capture startup marker was not observed' "$WORK_DIR/diagnostics.log" || fail 'startup timeout was not diagnosed'
    assert_safe_diagnostics "$WORK_DIR/diagnostics.log"
    local pid
    read -r pid <"$FAKE_PID_FILE"
    assert_reaped "$pid"
}

case_subscription_failure() {
    connect_stream_receiver() { return 1; }
    if start_capture_split "$WORK_DIR/stdout.log" "$WORK_DIR/stderr.log" >"$WORK_DIR/diagnostics.log" 2>&1; then
        fail 'capture with a failed subscription was accepted'
    fi
    local pid
    read -r pid <"$FAKE_PID_FILE"
    assert_reaped "$pid"
    connect_stream_receiver() { :; }
    start_capture_split "$WORK_DIR/stdout.log" "$WORK_DIR/stderr.log"
    pid="$CAPTURE_PID"
    stop_capture
    assert_reaped "$pid"
}

case_early_exit() {
    export FAKE_EARLY_EXIT=7 FAKE_DIAGNOSTICS=1
    if start_capture "$WORK_DIR/stdio.log" --output "$WORK_DIR/records.jsonl" >"$WORK_DIR/diagnostics.log" 2>&1; then
        fail 'capture exiting before readiness was accepted'
    fi
    grep -Fq 'exit=7' "$WORK_DIR/diagnostics.log" || fail 'original initialization exit status was lost'
    assert_safe_diagnostics "$WORK_DIR/diagnostics.log"
    local pid
    read -r pid <"$FAKE_PID_FILE"
    assert_reaped "$pid"
}

case_slow_stop() {
    # The former three-second drain budget would forcibly terminate this child.
    export FAKE_STOP_DELAY=4
    start_capture "$WORK_DIR/stdio.log"
    local pid="$CAPTURE_PID"
    stop_capture
    assert_reaped "$pid"
}

case_forced_stop() {
    export E2E_CAPTURE_STOP_TIMEOUT_SECONDS=1 FAKE_IGNORE_SIGNALS=1 FAKE_DIAGNOSTICS=1 FAKE_READY_TARGET=json
    start_capture "$WORK_DIR/stdio.log" --output "$WORK_DIR/records.jsonl"
    local pid="$CAPTURE_PID"
    if stop_capture >"$WORK_DIR/diagnostics.log" 2>&1; then
        fail 'forced termination was reported as successful'
    fi
    grep -Fq 'forced=1' "$WORK_DIR/diagnostics.log" || fail 'forced termination was not diagnosed'
    assert_safe_diagnostics "$WORK_DIR/diagnostics.log"
    assert_reaped "$pid"
}

case_failed_stop() {
    export FAKE_STOP_EXIT=7 FAKE_DIAGNOSTICS=1 FAKE_READY_TARGET=json
    start_capture "$WORK_DIR/stdio.log" --output "$WORK_DIR/records.jsonl"
    local pid="$CAPTURE_PID"
    if stop_capture >"$WORK_DIR/diagnostics.log" 2>&1; then
        fail 'capture with a nonzero shutdown status was accepted'
    fi
    grep -Fq 'exit=7' "$WORK_DIR/diagnostics.log" || fail 'shutdown exit status was lost'
    grep -Fq 'forced=0' "$WORK_DIR/diagnostics.log" || fail 'normal shutdown was reported as forced'
    assert_safe_diagnostics "$WORK_DIR/diagnostics.log"
    assert_reaped "$pid"
}

case_invalid_timeout() {
    local name value
    for name in E2E_CAPTURE_START_TIMEOUT_SECONDS E2E_CAPTURE_STOP_TIMEOUT_SECONDS; do
        for value in '' 0 08 -1 invalid 1.5 '1+1' 3601 1000000000 "\$(touch $WORK_DIR/injected)"; do
            export "$name=$value"
            if start_capture "$WORK_DIR/stdio.log" >"$WORK_DIR/diagnostics.log" 2>&1; then
                fail "accepted $name=$value"
            fi
            grep -Fq "$name must be a positive integer" "$WORK_DIR/diagnostics.log" || fail 'invalid timeout reason missing'
            [[ ! -e "$FAKE_PID_FILE" ]] || fail 'invalid timeout launched a capture'
            [[ ! -e "$WORK_DIR/injected" ]] || fail 'timeout evaluation executed a command'
            unset "$name"
        done
    done
    start_capture "$WORK_DIR/stdio.log"
    local pid="$CAPTURE_PID"
    export E2E_CAPTURE_STOP_TIMEOUT_SECONDS=0
    if stop_capture >"$WORK_DIR/diagnostics.log" 2>&1; then
        fail 'stop accepted an invalid timeout'
    fi
    kill -0 "$pid" || fail 'invalid stop timeout terminated the capture'
    unset E2E_CAPTURE_STOP_TIMEOUT_SECONDS
    stop_capture
    assert_reaped "$pid"
}

if [[ "${1:-}" == --case ]]; then
    name="$2"
    TEST_ROOT="$3"
    # shellcheck source=test/e2e/linux/common.sh
    source "$SCRIPT_DIR/common.sh"
    WORK_DIR="$TEST_ROOT/$name"
    mkdir -p "$WORK_DIR/helpers"
    ECAPTURE_BINARY="$TEST_ROOT/capture.py"
    export FAKE_PID_FILE="$WORK_DIR/capture.pid"
    unset E2E_CAPTURE_START_TIMEOUT_SECONDS E2E_CAPTURE_STOP_TIMEOUT_SECONDS
    unset FAKE_READY_DELAY FAKE_READY_TARGET FAKE_STOP_DELAY FAKE_STOP_EXIT FAKE_IGNORE_SIGNALS FAKE_EARLY_EXIT FAKE_DIAGNOSTICS
    # These projections/subscriptions are independent of process lifecycle.
    connect_stream_receiver() { :; }
    refresh_capture_outputs() { :; }
    cat >"$WORK_DIR/helpers/ecaptureq_assert" <<'SH'
#!/usr/bin/env bash
while (($#)); do
    if [[ "$1" == --extract-logs ]]; then : >"$2"; exit 0; fi
    shift
done
exit 1
SH
    chmod +x "$WORK_DIR/helpers/ecaptureq_assert"
    cleanup_case() {
        local status=$?
        trap - EXIT
        if [[ -n "$CAPTURE_PID" ]]; then
            kill -KILL "$CAPTURE_PID" 2>/dev/null || true
            wait "$CAPTURE_PID" 2>/dev/null || true
        fi
        exit "$status"
    }
    trap cleanup_case EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    case "$name" in
        json_ready|split_ready|slow_start|start_timeout|subscription_failure|early_exit|slow_stop|forced_stop|failed_stop|invalid_timeout)
            "case_$name" ;;
        *) fail "unknown case $name" ;;
    esac
    exit 0
fi

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
cat >"$TEST_ROOT/capture.py" <<'PY'
#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--output', action='append', default=[])
args = parser.parse_args()
Path(os.environ['FAKE_PID_FILE']).write_text(str(os.getpid()) + '\n')
ready_at = time.monotonic() + float(os.getenv('FAKE_READY_DELAY', '0'))
stop_at = None
ready = False

def stop(signum, frame):
    global stop_at
    if os.getenv('FAKE_IGNORE_SIGNALS') != '1' and stop_at is None:
        stop_at = time.monotonic() + float(os.getenv('FAKE_STOP_DELAY', '0'))

signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)

def write_json(record):
    for output in args.output:
        with open(output, 'a') as stream:
            stream.write(json.dumps(record) + '\n')

if os.getenv('FAKE_DIAGNOSTICS') == '1':
    write_json({'log_type': 'LOG_TYPE_PROCESS_LOG', 'run_log': json.dumps({
        'time': '2026-11-21T00:00:00Z', 'level': 'error',
        'message': 'LIFECYCLE_LOG_SENTINEL', 'error': 'fixture failure',
        'collector': 'COLLECTOR_PRIVATE_SECRET', 'argv': ['ARGV_PRIVATE_SECRET'],
        'metadata': {'private': 'METADATA_PRIVATE_SECRET'}})})
    write_json({'logType': 1, 'runLog': json.dumps({
        'message': 'NESTED_LOG_SENTINEL', 'error': 'fixture failure',
        'secret': 'NESTED_PRIVATE_SECRET', 'collector': {'data': 'COLLECTOR_PRIVATE_SECRET'}})})
    write_json({'log_type': 1, 'run_log': {'message': 'NONSTRING_PRIVATE_SECRET'}})
    write_json({'logType': 1, 'runLog': 'MIXED_PRIVATE_SECRET', 'eventPayload': {}})
    write_json({'log_type': 'LOG_TYPE_EVENT', 'event_payload': {
        'capture_format': 'CAPTURE_FORMAT_TEXT', 'text': {'payload': 'RVZFTlRfUFJJVkFURV9TRUNSRVQ='}}})
    write_json({'log_type': 'LOG_TYPE_EVENT', 'event_payload': {
        'capture_format': 'CAPTURE_FORMAT_KEYLOG', 'keylog': {'data': 'S0VZTE9HX1BSSVZBVEVfU0VDUkVU'}}})
    for output in args.output:
        with open(output, 'a') as stream:
            stream.write('{"log_type":"LOG_TYPE_PROCESS_LOG","run_log":"MALFORMED_PRIVATE_SECRET"\n')
    print('[log_type=log module=fixture] TERMINAL_LOG_SENTINEL', flush=True)
    print('[log_type=event capture_format=keylog module=fixture] CLIENT_RANDOM KEYLOG_PRIVATE_SECRET', flush=True)
    print('UNCLASSIFIED_PRIVATE_SECRET', file=sys.stderr, flush=True)

if 'FAKE_EARLY_EXIT' in os.environ:
    sys.exit(int(os.environ['FAKE_EARLY_EXIT']))

while True:
    now = time.monotonic()
    if stop_at is not None and now >= stop_at:
        sys.exit(int(os.getenv('FAKE_STOP_EXIT', '0')))
    if not ready and now >= ready_at:
        ready = True
        target = os.getenv('FAKE_READY_TARGET', 'stdout')
        if target == 'json':
            write_json({'log_type': 'LOG_TYPE_PROCESS_LOG', 'run_log': 'probe started successfully'})
        elif target in ('stdout', 'stderr'):
            print('[log_type=log module=fixture] probe started successfully',
                  file=getattr(sys, target), flush=True)
    time.sleep(0.01)
PY
chmod +x "$TEST_ROOT/capture.py"

checks=0
for name in json_ready split_ready slow_start start_timeout subscription_failure early_exit slow_stop forced_stop failed_stop invalid_timeout; do
    if ! bash "$0" --case "$name" "$TEST_ROOT" >"$TEST_ROOT/$name.result" 2>&1; then
        cat "$TEST_ROOT/$name.result" >&2
        fail "$name"
    fi
    checks=$((checks + 1))
done
printf 'PASS: %d Linux capture lifecycle checks\n' "$checks"
