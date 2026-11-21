#!/usr/bin/env bash
# GnuTLS probe E2E tests for supported Ubuntu and Debian hosts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/linux/common.sh
source "$SCRIPT_DIR/common.sh"

GNUTLS_CLIENT=""
GNUTLS_LIB=""

build_gnutls_client() {
    require_command pkg-config
    if ! pkg-config --exists gnutls; then
        log_error "GnuTLS development package not found (install libgnutls28-dev)"
        return 1
    fi
    GNUTLS_CLIENT="$WORK_DIR/helpers/gnutls_client"
    # Word splitting is intentional for pkg-config compiler/linker flags.
    # shellcheck disable=SC2046
    cc -O2 -Wall -Wextra -Werror $(pkg-config --cflags gnutls) \
        -o "$GNUTLS_CLIENT" "$E2E_DIR/fixtures/c/gnutls_client.c" $(pkg-config --libs gnutls)
    GNUTLS_LIB="$(resolve_linked_library "$GNUTLS_CLIENT" 'libgnutls[.]so')"
    log_info "GnuTLS fixture library: $GNUTLS_LIB"
}

run_gnutls_request() {
    local tls_version="$1"
    local output_file="$2"
    timeout 15 "$GNUTLS_CLIENT" 127.0.0.1 "$TLS_SERVER_PORT" /e2e "$E2E_TOKEN" "$tls_version" \
        >"$output_file" 2>&1
    assert_file_contains "$output_file" "$E2E_TOKEN" "GnuTLS fixture response"
}

case_invalid_output_combinations() {
    local output="$WORK_DIR/invalid-output.log"
    if "$ECAPTURE_BINARY" gnutls --gnutls "$GNUTLS_LIB" --model keylog \
        --output "$WORK_DIR/records.jsonl" >"$output" 2>&1; then
        log_error "keylog capture without --keylogfile unexpectedly succeeded"
        return 1
    fi
    assert_file_contains "$output" "requires --keylogfile" "missing native artifact rejection" || return 1
    if "$ECAPTURE_BINARY" gnutls --gnutls "$GNUTLS_LIB" --model text --text-source hook \
        --output udp://127.0.0.1:9000 >"$output" 2>&1; then
        log_error "unsupported output scheme unexpectedly succeeded"
        return 1
    fi
    assert_file_contains "$output" "unsupported --output scheme" "unsupported scheme rejection" || return 1
    if "$ECAPTURE_BINARY" gnutls --gnutls "$GNUTLS_LIB" --model pcapng --ifname lo \
        --output stdout --pcapfile stdout >"$output" 2>&1; then
        log_error "native pcapng artifact on stdout unexpectedly succeeded"
        return 1
    fi
    assert_file_contains "$output" "terminal destination" "native terminal rejection" || return 1
    if "$ECAPTURE_BINARY" gnutls --gnutls "$GNUTLS_LIB" --eventaddr "$WORK_DIR/old" >"$output" 2>&1; then
        log_error "removed --eventaddr unexpectedly succeeded"
        return 1
    fi
    assert_file_contains "$output" "unknown flag: --eventaddr" "removed CLI parameter rejection"
}

case_text() {
    local capture_log="$WORK_DIR/text.ecapture.log"
    local operational_log="$WORK_DIR/text.operational.log"
    local event_file="$WORK_DIR/text.events.log"
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model text --text-source hook \
        --output "$operational_log.logs.jsonl" --output "$event_file.events.jsonl" || return 1
    if ! run_gnutls_request tls13 "$WORK_DIR/text.client.log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "captured GnuTLS plaintext" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    print_plaintext_preview "$event_file" "$E2E_TOKEN" "linux/gnutls/text"
}

case_keylog() {
    local capture_log="$WORK_DIR/keylog.ecapture.log"
    local operational_log="$WORK_DIR/keylog.operational.log"
    local keylog_file="$WORK_DIR/gnutls.keys.log"
    local packet_file="$WORK_DIR/gnutls.keylog.pcapng"
    local packet_log="$WORK_DIR/gnutls.keylog.tshark-capture.log"
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || return 1
    if ! start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model keylog \
        --output "$operational_log.logs.jsonl" --keylogfile "$keylog_file"; then
        stop_packet_capture
        return 1
    fi
    if ! run_gnutls_request tls12 "$WORK_DIR/keylog.tls12.client.log" || \
       ! run_gnutls_request tls13 "$WORK_DIR/keylog.tls13.client.log"; then
        stop_capture
        stop_packet_capture
        return 1
    fi
    sleep 1
    stop_capture
    stop_packet_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$keylog_file" "$E2E_TOKEN" || return 1
    assert_file_not_contains "$operational_log" "CLIENT_RANDOM " "TLS secret in operational log" || return 1
    assert_keylog "$keylog_file" || return 1
    grep -Eq '^CLIENT_RANDOM ' "$keylog_file" || {
        log_error "GnuTLS TLS 1.2 CLIENT_RANDOM was not captured"
        return 1
    }
    grep -Eq '^(CLIENT|SERVER)_(HANDSHAKE_)?TRAFFIC_SECRET' "$keylog_file" || {
        log_error "GnuTLS TLS 1.3 traffic secret was not captured"
        return 1
    }
    assert_tls_plaintext_preview \
        "$packet_file" "$keylog_file" "$E2E_TOKEN" "linux/gnutls/keylog" 0 || return 1
    assert_tls_plaintext_preview \
        "$packet_file" "$keylog_file" "$E2E_TOKEN" "linux/gnutls/keylog" 1
}

case_pcapng() {
    local capture_log="$WORK_DIR/pcapng.ecapture.log"
    local operational_log="$WORK_DIR/pcapng.operational.log"
    local pcap_file="$WORK_DIR/gnutls.pcapng"
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model pcapng \
        --output "$operational_log.logs.jsonl" --ifname lo --pcapfile "$pcap_file" \
        --keylogfile= "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_gnutls_request tls13 "$WORK_DIR/pcapng.client.log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$pcap_file" "$E2E_TOKEN" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng_plaintext_preview \
        "$pcap_file" "$E2E_TOKEN" "linux/gnutls/pcapng"
}

case_text_pcapng() {
    local capture_log="$WORK_DIR/decrypt.ecapture.log"
    local operational_log="$WORK_DIR/decrypt.operational.log"
    local event_file="$WORK_DIR/decrypt.events.log"
    local pcap_file="$WORK_DIR/decrypt.pcapng"
    start_capture_split "$event_file.console" "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model text \
        --output stdout --output "$operational_log.logs.jsonl" --ifname lo \
        --pcapfile "$pcap_file" "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_gnutls_request tls13 "$WORK_DIR/decrypt.client.log"; then
        stop_capture
        return 1
    fi
    if ! wait_for_file_contains "$event_file.console" "$E2E_TOKEN" "live decrypted HTTP response"; then
        stop_capture
        return 1
    fi
    if ! run_gnutls_request tls12 "$WORK_DIR/decrypt.tls12.client.log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "decrypted HTTP response" || return 1
    grep -Eq 'http/(1\.1|2) request .*host="[^"]+"' "$event_file" || return 1
    grep -Eq 'http/(1\.1|2) response .*host="[^"]+"' "$event_file" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    assert_file_not_contains "$operational_log" "CLIENT_RANDOM " "TLS secret in operational log" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_http_event_timestamps_current "$event_file" "linux/gnutls/text-pcapng" || return 1
    assert_pcapng_plaintext_preview "$pcap_file" "$E2E_TOKEN" "linux/gnutls/text-pcapng" || return 1
}

case_text_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/text-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/text-${transport}.operational.log"
    local event_file="$WORK_DIR/text-${transport}.events.log"
    start_output_receiver "$transport" "$event_file" || return 1
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model text --text-source hook \
        --output "$operational_log.logs.jsonl" --"$OUTPUT_RECEIVER_FLAG" "$OUTPUT_RECEIVER_URI" || {
        stop_output_receiver || true
        return 1
    }
    run_gnutls_request tls13 "$WORK_DIR/text-${transport}.client.log" || {
        stop_capture
        stop_output_receiver || true
        return 1
    }
    sleep 1
    stop_capture
    stop_output_receiver || return 1
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "${transport} text output" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    print_plaintext_preview "$event_file" "$E2E_TOKEN" "linux/gnutls/text-${transport}"
}

case_text_stdout() {
    local destination="${1:-stdout}"
    local capture_log="$WORK_DIR/text-${destination}.ecapture.log"
    local operational_log="$WORK_DIR/text-${destination}.operational.log"
    local event_file="$WORK_DIR/text.${destination}.events.log"
    local stdout_file="$event_file.console" stderr_file="$capture_log"
    if [[ "$destination" == stderr ]]; then
        stdout_file="$capture_log"; stderr_file="$event_file.console"
    fi
    start_capture_split "$stdout_file" "$stderr_file" gnutls --gnutls "$GNUTLS_LIB" \
        --model text --text-source hook --output "$destination" --output "$operational_log.logs.jsonl" || return 1
    if ! run_gnutls_request tls13 "$WORK_DIR/text-stdout.client.log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "stdout text output" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    print_plaintext_preview "$event_file" "$E2E_TOKEN" "linux/gnutls/text-stdout"
}

case_operational_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/combined-${transport}.ecapture.log"
    local event_file="$WORK_DIR/combined-${transport}.events.log"
    local remote_file="$WORK_DIR/combined-${transport}.remote.events.log"
    start_output_receiver "$transport" "$remote_file" || return 1
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model text --text-source hook \
        --"$OUTPUT_RECEIVER_FLAG" "$OUTPUT_RECEIVER_URI" --output "$event_file.events.jsonl" || {
        stop_output_receiver || true
        return 1
    }
    if ! run_gnutls_request tls13 "$WORK_DIR/combined-${transport}.client.log"; then
        stop_capture
        stop_output_receiver || true
        return 1
    fi
    sleep 1
    stop_capture
    stop_output_receiver || return 1
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "file text event" || return 1
    assert_file_contains "$remote_file" "$E2E_TOKEN" "network text event" || return 1
    assert_output_isolation "$remote_file.runtime.log" "$remote_file" "$E2E_TOKEN"
}

case_operational_stdout() {
    local capture_log="$WORK_DIR/combined-stdout.ecapture.log"
    local terminal_file="$WORK_DIR/combined.stdout.console"
    local event_file="$WORK_DIR/combined-stdout.events.log"
    start_capture_split "$terminal_file" "$capture_log" gnutls --gnutls "$GNUTLS_LIB" \
        --model text --text-source hook --output stdout --output "$event_file.events.jsonl" || return 1
    if ! run_gnutls_request tls13 "$WORK_DIR/combined-stdout.client.log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "captured text event" || return 1
    assert_file_contains "$terminal_file" "[log_type=log module=gnutls]" "terminal runtime log marker" || return 1
    assert_file_contains "$terminal_file" "[log_type=event capture_format=text module=gnutls]" "terminal event marker" || return 1
    assert_file_contains "$terminal_file" "$E2E_TOKEN" "terminal text event"
}

case_keylog_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/keylog-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/keylog-${transport}.operational.log"
    local keylog_file="$WORK_DIR/gnutls.${transport}.keys.log"
    local packet_file="$WORK_DIR/gnutls.${transport}.pcapng"
    local packet_log="$WORK_DIR/gnutls.${transport}.tshark-capture.log"
    start_output_receiver "$transport" "$keylog_file" keylog || return 1
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || {
        stop_output_receiver || true
        return 1
    }
    if ! start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model keylog \
        --output "$operational_log.logs.jsonl" --"$OUTPUT_RECEIVER_FLAG" "$OUTPUT_RECEIVER_URI" \
        --keylogfile "$keylog_file.local"; then
        stop_packet_capture
        stop_output_receiver || true
        return 1
    fi
    if ! run_gnutls_request tls13 "$WORK_DIR/keylog-${transport}.client.log"; then
        stop_capture
        stop_packet_capture
        stop_output_receiver || true
        return 1
    fi
    sleep 1
    stop_capture
    stop_packet_capture
    stop_output_receiver || return 1
    assert_no_capture_errors "$capture_log" || return 1
    assert_keylog "$keylog_file" || return 1
    assert_keylog "$keylog_file.local" || return 1
    cmp "$keylog_file" "$keylog_file.local" || return 1
    assert_file_not_contains "$operational_log" "TRAFFIC_SECRET" "TLS secret in operational log" || return 1
    assert_tls_plaintext_preview "$packet_file" "$keylog_file" "$E2E_TOKEN" \
        "linux/gnutls/keylog-${transport}"
}

case_keylog_stdout() {
    local capture_log="$WORK_DIR/keylog-stdout.ecapture.log"
    local operational_log="$WORK_DIR/keylog-stdout.operational.log"
    local keylog_file="$WORK_DIR/gnutls.stdout.keys.log"
    local packet_file="$WORK_DIR/gnutls.stdout-keylog.pcapng"
    local packet_log="$WORK_DIR/gnutls.stdout-keylog.tshark-capture.log"
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || return 1
    if ! start_capture_split "$keylog_file.terminal.console" "$capture_log" gnutls --gnutls "$GNUTLS_LIB" \
        --model keylog --keylogfile "$keylog_file" --output stdout --output "$operational_log.logs.jsonl"; then
        stop_packet_capture
        return 1
    fi
    if ! run_gnutls_request tls13 "$WORK_DIR/keylog-stdout.client.log"; then
        stop_capture
        stop_packet_capture
        return 1
    fi
    sleep 1
    stop_capture
    stop_packet_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$keylog_file" "$E2E_TOKEN" || return 1
    assert_file_not_contains "$operational_log" "TRAFFIC_SECRET" \
        "TLS secret in operational log" || return 1
    assert_keylog "$keylog_file" || return 1
    assert_file_contains "$keylog_file.terminal.console" "[log_type=event capture_format=keylog module=gnutls]" "terminal keylog classification" || return 1
    assert_tls_plaintext_preview "$packet_file" "$keylog_file" "$E2E_TOKEN" \
        "linux/gnutls/keylog-stdout"
}

case_pcapng_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/pcapng-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/pcapng-${transport}.operational.log"
    local pcap_file="$WORK_DIR/gnutls.${transport}.pcapng"
    start_output_receiver "$transport" "$pcap_file" pcapng || return 1
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model pcapng \
        --output "$operational_log.logs.jsonl" --"$OUTPUT_RECEIVER_FLAG" "$OUTPUT_RECEIVER_URI" \
        --pcapfile "$pcap_file.local" --ifname lo --keylogfile= "tcp port $TLS_SERVER_PORT" || {
        stop_output_receiver || true
        return 1
    }
    if ! run_gnutls_request tls13 "$WORK_DIR/pcapng-${transport}.client.log"; then
        stop_capture
        stop_output_receiver || true
        return 1
    fi
    sleep 2
    stop_capture
    stop_output_receiver || return 1
    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$pcap_file" "$E2E_TOKEN" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng "$pcap_file.local" || return 1
    if [[ "$transport" == tcp ]]; then
        cmp "$pcap_file" "$pcap_file.local" || return 1
    fi
    assert_pcapng_plaintext_preview "$pcap_file" "$E2E_TOKEN" \
        "linux/gnutls/pcapng-${transport}"
}

case_pcapng_stdout() {
    local capture_log="$WORK_DIR/pcapng-stdout.ecapture.log"
    local operational_log="$WORK_DIR/pcapng-stdout.operational.log"
    local pcap_file="$WORK_DIR/gnutls.stdout.pcapng"
    start_capture_split "$pcap_file.terminal.console" "$capture_log" gnutls --gnutls "$GNUTLS_LIB" \
        --model pcapng --pcapfile "$pcap_file" --output stdout --output "$operational_log.logs.jsonl" \
        --ifname lo --keylogfile= "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_gnutls_request tls13 "$WORK_DIR/pcapng-stdout.client.log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$pcap_file" "$E2E_TOKEN" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng_terminal_logs "$pcap_file.terminal.console" gnutls || return 1
    assert_pcapng_plaintext_preview "$pcap_file" "$E2E_TOKEN" "linux/gnutls/pcapng-stdout"
}

case_ecaptureq_text() {
    local capture_log="$WORK_DIR/ecaptureq-text.ecapture.log"
    local operational_log="$WORK_DIR/ecaptureq-text.operational.log"
    local event_file="$WORK_DIR/ecaptureq-text.events.log"
    local client_log="$WORK_DIR/ecaptureq-text.client.log"
    local port=$((30000 + RANDOM % 20000))
    local endpoint="ws://127.0.0.1:${port}/"
    "$WORK_DIR/helpers/ecaptureq_assert" --server "$endpoint" --format text \
        --token "$E2E_TOKEN" --module gnutls --ready-file "$client_log.ready" >"$client_log" 2>&1 &
    local client_pid=$!
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model text --text-source hook \
        --output "$operational_log.logs.jsonl" --output "$event_file.events.jsonl" --stream-listen "$endpoint" || {
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    wait_for_receiver_ready "$client_log.ready" "$client_pid" || {
        stop_capture
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    run_gnutls_request tls13 "$WORK_DIR/ecaptureq-text.request.log" || {
        stop_capture
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    local client_status=0
    wait "$client_pid" || client_status=$?
    stop_capture
    if ((client_status != 0)); then
        log_error "Strict eCaptureQ client failed"
        cat "$client_log" >&2 || true
        return 1
    fi
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$client_log" \
        "PROCESS_LOG=1 EVENT=1 FORMAT=CAPTURE_FORMAT_TEXT METADATA=1" \
        "typed eCaptureQ dual-channel result" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "additive raw text event" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN"
}

case_ecaptureq_keylog() {
    local capture_log="$WORK_DIR/ecaptureq-keylog.ecapture.log"
    local operational_log="$WORK_DIR/ecaptureq-keylog.operational.log"
    local keylog_file="$WORK_DIR/ecaptureq-keylog.keys.log"
    local client_log="$WORK_DIR/ecaptureq-keylog.client.log"
    local port=$((30000 + RANDOM % 20000))
    local endpoint="ws://127.0.0.1:${port}/"
    "$WORK_DIR/helpers/ecaptureq_assert" --server "$endpoint" --format keylog --module gnutls \
        --ready-file "$client_log.ready" --capture-file "$keylog_file.ws" --drain >"$client_log" 2>&1 &
    local client_pid=$!
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model keylog \
        --output "$operational_log.logs.jsonl" --keylogfile "$keylog_file" --stream-listen "$endpoint" || {
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    wait_for_receiver_ready "$client_log.ready" "$client_pid" || {
        stop_capture
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    if ! run_gnutls_request tls13 "$WORK_DIR/ecaptureq-keylog.request.log"; then
        stop_capture
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    fi
    local client_status=0
    sleep 2
    stop_capture
    wait "$client_pid" || client_status=$?
    if ((client_status != 0)); then
        log_error "Strict eCaptureQ keylog receiver failed"
        cat "$client_log" >&2 || true
        return 1
    fi
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$client_log" \
        "PROCESS_LOG=1 EVENT=1 FORMAT=CAPTURE_FORMAT_KEYLOG NATIVE=1" \
        "typed eCaptureQ keylog receiver result" || return 1
    assert_keylog "$keylog_file" || return 1
    assert_keylog "$keylog_file.ws" || return 1
    cmp "$keylog_file" "$keylog_file.ws" || return 1
    assert_output_isolation "$operational_log" "$keylog_file" "$E2E_TOKEN" || return 1
    assert_file_not_contains "$operational_log" "TRAFFIC_SECRET" \
        "TLS secret in operational log"
}

case_ecaptureq_pcapng() {
    local capture_log="$WORK_DIR/ecaptureq-pcapng.ecapture.log"
    local operational_log="$WORK_DIR/ecaptureq-pcapng.operational.log"
    local pcap_file="$WORK_DIR/ecaptureq-pcapng.pcapng"
    local client_log="$WORK_DIR/ecaptureq-pcapng.client.log"
    local port=$((30000 + RANDOM % 20000))
    local endpoint="ws://127.0.0.1:${port}/"
    "$WORK_DIR/helpers/ecaptureq_assert" --server "$endpoint" --format pcapng --module gnutls \
        --ready-file "$client_log.ready" --capture-file "$pcap_file.ws" --drain >"$client_log" 2>&1 &
    local client_pid=$!
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model pcapng \
        --output "$operational_log.logs.jsonl" --pcapfile "$pcap_file" --stream-listen "$endpoint" \
        --ifname lo --keylogfile= "tcp port $TLS_SERVER_PORT" || {
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    wait_for_receiver_ready "$client_log.ready" "$client_pid" || {
        stop_capture
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    if ! run_gnutls_request tls13 "$WORK_DIR/ecaptureq-pcapng.request.log"; then
        stop_capture
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    fi
    local client_status=0
    sleep 2
    stop_capture
    wait "$client_pid" || client_status=$?
    if ((client_status != 0)); then
        log_error "Strict eCaptureQ pcapng receiver failed"
        cat "$client_log" >&2 || true
        return 1
    fi
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$client_log" \
        "PROCESS_LOG=1 EVENT=1 FORMAT=CAPTURE_FORMAT_PCAPNG NATIVE=1" \
        "typed eCaptureQ pcapng receiver result" || return 1
    assert_output_isolation "$operational_log" "$pcap_file" "$E2E_TOKEN" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng "$pcap_file.ws" || return 1
    assert_pcapng_plaintext_preview "$pcap_file.ws" "$E2E_TOKEN" "linux/gnutls/stream-pcapng" || return 1
    assert_pcapng_plaintext_preview \
        "$pcap_file" "$E2E_TOKEN" "linux/gnutls/ecaptureq-pcapng"
}

case_text_reload_output() {
    local capture_log="$WORK_DIR/reload.ecapture.log"
    local operational_log="$WORK_DIR/reload.operational.log"
    local event_file="$WORK_DIR/reload.events.log"
    local forbidden_file="$WORK_DIR/reload-forbidden.events.log"
    local port=$((30000 + RANDOM % 20000))
    local endpoint="http://127.0.0.1:$port/gnutls"
    local before_token="${E2E_TOKEN}_RELOAD_BEFORE"
    local after_token="${E2E_TOKEN}_RELOAD_AFTER"
    local rejected_token="${E2E_TOKEN}_RELOAD_REJECTED"
    local request_body="$WORK_DIR/reload-request.json"
    local response_body="$WORK_DIR/reload-response.json"

    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model text --text-source hook \
        --config-listen "127.0.0.1:$port" \
        --output "$operational_log.logs.jsonl" --output "$event_file.events.jsonl" || return 1
    timeout 15 "$GNUTLS_CLIENT" 127.0.0.1 "$TLS_SERVER_PORT" \
        "/e2e?marker=$before_token" "$E2E_TOKEN" tls13 \
        >"$WORK_DIR/reload-before.client.log" 2>&1 || { stop_capture; return 1; }
    wait_for_file_contains "$event_file" "$before_token" "GnuTLS event before reload" || {
        stop_capture; return 1;
    }

    printf '{"gnutlspath":"%s","capturemode":"text","text_source":"hook"}\n' "$GNUTLS_LIB" >"$request_body"
    post_config_update "$endpoint" "$request_body" "$response_body" 1 || { stop_capture; return 1; }
    timeout 15 "$GNUTLS_CLIENT" 127.0.0.1 "$TLS_SERVER_PORT" \
        "/e2e?marker=$after_token" "$E2E_TOKEN" tls13 \
        >"$WORK_DIR/reload-after.client.log" 2>&1 || { stop_capture; return 1; }
    wait_for_file_contains "$event_file" "$after_token" "GnuTLS unchanged process output after reload" || {
        stop_capture; return 1;
    }

    printf '{"gnutlspath":"%s","capturemode":"text","text_source":"hook","event_collector_addr":"%s"}\n' \
        "$GNUTLS_LIB" "$forbidden_file" >"$request_body"
    post_config_update "$endpoint" "$request_body" "$response_body" 0 || { stop_capture; return 1; }
    timeout 15 "$GNUTLS_CLIENT" 127.0.0.1 "$TLS_SERVER_PORT" \
        "/e2e?marker=$rejected_token" "$E2E_TOKEN" tls13 \
        >"$WORK_DIR/reload-rejected.client.log" 2>&1 || { stop_capture; return 1; }
    wait_for_file_contains "$event_file" "$rejected_token" "GnuTLS output after rejected legacy-field update" || {
        stop_capture; return 1;
    }
    stop_capture
    [[ ! -e "$forbidden_file" ]] || { log_error "Rejected output file was created"; return 1; }
    assert_file_contains "$event_file" "$before_token" "retained pre-reload event" || return 1
    assert_file_contains "$event_file" "$after_token" "retained post-reload event" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    assert_no_capture_errors "$capture_log"
}

main() {
    setup_linux_suite gnutls
    build_gnutls_client

    run_case "linux/gnutls/invalid-output-combinations" case_invalid_output_combinations
    mode_enabled text && run_case "linux/gnutls/text" case_text
    mode_enabled text && run_case "linux/gnutls/text-reload-output" case_text_reload_output
    mode_enabled text && run_case "linux/gnutls/text-stdout" case_text_stdout
    mode_enabled text && run_case "linux/gnutls/text-stderr" case_text_stdout stderr
    mode_enabled text && run_case "linux/gnutls/text-tcp" case_text_stream tcp
    mode_enabled text && run_case "linux/gnutls/text-websocket" case_text_stream ws
    mode_enabled text && run_case "linux/gnutls/combined-output-stdout" case_operational_stdout
    mode_enabled text && run_case "linux/gnutls/combined-output-tcp" case_operational_stream tcp
    mode_enabled text && run_case "linux/gnutls/combined-output-websocket" case_operational_stream ws
    mode_enabled text && run_case "linux/gnutls/ecaptureq-receiver-text" case_ecaptureq_text
    mode_enabled keylog && run_case "linux/gnutls/keylog-tls12-tls13" case_keylog
    mode_enabled keylog && run_case "linux/gnutls/keylog-stdout" case_keylog_stdout
    mode_enabled keylog && run_case "linux/gnutls/keylog-tcp" case_keylog_stream tcp
    mode_enabled keylog && run_case "linux/gnutls/keylog-websocket" case_keylog_stream ws
    mode_enabled keylog && run_case "linux/gnutls/ecaptureq-receiver-keylog" case_ecaptureq_keylog
    mode_enabled pcapng && run_case "linux/gnutls/pcapng-with-dsb" case_pcapng
    mode_enabled pcapng && run_case "linux/gnutls/pcapng-tcp" case_pcapng_stream tcp
    mode_enabled pcapng && run_case "linux/gnutls/pcapng-websocket" case_pcapng_stream ws
    mode_enabled pcapng && run_case "linux/gnutls/pcapng-stdout" case_pcapng_stdout
    mode_enabled pcapng && run_case "linux/gnutls/ecaptureq-receiver-pcapng" case_ecaptureq_pcapng
    mode_enabled text && run_case "linux/gnutls/text-pcapng-http-default-source" case_text_pcapng

    print_summary "Linux GnuTLS E2E"
}

main "$@"
