#!/usr/bin/env bash
# OpenSSL TLS probe E2E tests for Ubuntu 22.04+.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/linux/common.sh
source "$SCRIPT_DIR/common.sh"

OPENSSL_CLIENT=""
OPENSSL_LIB=""

build_openssl_client() {
    OPENSSL_CLIENT="$WORK_DIR/helpers/openssl_client"
    cc -O2 -Wall -Wextra -Werror \
        -o "$OPENSSL_CLIENT" "$E2E_DIR/fixtures/c/openssl_client.c" -lssl -lcrypto
    OPENSSL_LIB="$(resolve_linked_library "$OPENSSL_CLIENT" 'libssl[.]so')"
    log_info "OpenSSL fixture library: $OPENSSL_LIB"
}

run_openssl_request() {
    local tls_version="$1"
    local output_file="$2"
    timeout 15 "$OPENSSL_CLIENT" 127.0.0.1 "$TLS_SERVER_PORT" /e2e "$E2E_TOKEN" "$tls_version" \
        >"$output_file" 2>&1
    assert_file_contains "$output_file" "$E2E_TOKEN" "OpenSSL fixture response"
}

run_openssl_burst() {
    local client_log="$1"
    local requests=256
    local concurrency=64
    local request pid failures=0
    local -a pids=()

    : >"$client_log"
    for ((request = 1; request <= requests; request++)); do
        timeout 15 "$OPENSSL_CLIENT" 127.0.0.1 "$TLS_SERVER_PORT" /e2e "$E2E_TOKEN" tls13 \
            >/dev/null 2>>"$client_log" &
        pids+=("$!")

        if ((${#pids[@]} == concurrency || request == requests)); then
            for pid in "${pids[@]}"; do
                if ! wait "$pid"; then
                    failures=$((failures + 1))
                fi
            done
            pids=()
        fi
    done

    if ((failures > 0)); then
        log_error "$failures of $requests OpenSSL burst requests failed"
        tail -n 80 "$client_log" >&2 || true
        return 1
    fi
}

case_invalid_output_combinations() {
    local output="$WORK_DIR/invalid-output.log"
    if "$ECAPTURE_BINARY" tls --libssl "$OPENSSL_LIB" --model keylog \
        --eventaddr "$WORK_DIR/a.keys" --keylogfile "$WORK_DIR/b.keys" >"$output" 2>&1; then
        log_error "conflicting --eventaddr/--keylogfile unexpectedly succeeded"
        return 1
    fi
    assert_file_contains "$output" "cannot both select" "legacy destination conflict" || return 1
    if "$ECAPTURE_BINARY" tls --libssl "$OPENSSL_LIB" --model text \
        --eventaddr udp://127.0.0.1:9000 >"$output" 2>&1; then
        log_error "unsupported event scheme unexpectedly succeeded"
        return 1
    fi
    assert_file_contains "$output" "unsupported sink URI scheme" "unsupported scheme rejection" || return 1
    if "$ECAPTURE_BINARY" tls --libssl "$OPENSSL_LIB" --model pcapng --ifname lo \
        --eventaddr stdout --logaddr stdout --keylogfile= >"$output" 2>&1; then
        log_error "pcapng and operational stdout collision unexpectedly succeeded"
        return 1
    fi
    assert_file_contains "$output" "cannot both use stdout" "stdout collision rejection"
}

case_text() {
    local capture_log="$WORK_DIR/text.ecapture.log"
    local operational_log="$WORK_DIR/text.operational.log"
    local event_file="$WORK_DIR/text.events.log"
    local client_log="$WORK_DIR/text.client.log"
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model text \
        --logaddr "$operational_log" --eventaddr "$event_file" || return 1
    if ! run_openssl_request tls13 "$client_log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "captured OpenSSL plaintext" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    print_plaintext_preview "$event_file" "$E2E_TOKEN" "linux/tls/text"
}

case_keylog() {
    local capture_log="$WORK_DIR/keylog.ecapture.log"
    local operational_log="$WORK_DIR/keylog.operational.log"
    local keylog_file="$WORK_DIR/openssl.keys.log"
    local packet_file="$WORK_DIR/openssl.keylog.pcapng"
    local packet_log="$WORK_DIR/openssl.keylog.tshark-capture.log"
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || return 1
    if ! start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model keylog \
        --logaddr "$operational_log" --keylogfile "$keylog_file"; then
        stop_packet_capture
        return 1
    fi
    if ! run_openssl_request tls12 "$WORK_DIR/keylog.tls12.client.log" || \
       ! run_openssl_request tls13 "$WORK_DIR/keylog.tls13.client.log"; then
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
        log_error "OpenSSL TLS 1.2 CLIENT_RANDOM was not captured"
        return 1
    }
    grep -Eq '^(CLIENT|SERVER)_(HANDSHAKE_)?TRAFFIC_SECRET' "$keylog_file" || {
        log_error "OpenSSL TLS 1.3 traffic secret was not captured"
        return 1
    }
    assert_tls_plaintext_preview \
        "$packet_file" "$keylog_file" "$E2E_TOKEN" "linux/tls/keylog"
}

case_pcapng() {
    local capture_log="$WORK_DIR/pcapng.ecapture.log"
    local operational_log="$WORK_DIR/pcapng.operational.log"
    local pcap_file="$WORK_DIR/openssl.pcapng"
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model pcapng \
        --logaddr "$operational_log" --ifname lo --pcapfile "$pcap_file" \
        --keylogfile= "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_openssl_request tls13 "$WORK_DIR/pcapng.client.log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$pcap_file" "$E2E_TOKEN" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng_plaintext_preview \
        "$pcap_file" "$E2E_TOKEN" "linux/tls/pcapng"
}

case_text_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/text-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/text-${transport}.operational.log"
    local event_file="$WORK_DIR/text-${transport}.events.log"
    start_output_receiver "$transport" "$event_file" || return 1
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model text \
        --logaddr "$operational_log" --eventaddr "$OUTPUT_RECEIVER_URI" || {
        stop_output_receiver || true
        return 1
    }
    run_openssl_request tls13 "$WORK_DIR/text-${transport}.client.log" || {
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
    print_plaintext_preview "$event_file" "$E2E_TOKEN" "linux/tls/text-${transport}"
}

case_text_stdout() {
    local capture_log="$WORK_DIR/text-stdout.ecapture.log"
    local operational_log="$WORK_DIR/text-stdout.operational.log"
    local event_file="$WORK_DIR/text.stdout.events.log"
    start_capture_split "$event_file" "$capture_log" tls --libssl "$OPENSSL_LIB" \
        --model text --eventaddr stdout --logaddr "$operational_log" || return 1
    if ! run_openssl_request tls13 "$WORK_DIR/text-stdout.client.log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "stdout text output" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    print_plaintext_preview "$event_file" "$E2E_TOKEN" "linux/tls/text-stdout"
}

case_operational_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/logaddr-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/logaddr-${transport}.operational.log"
    local event_file="$WORK_DIR/logaddr-${transport}.events.log"
    start_output_receiver "$transport" "$operational_log" || return 1
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model text \
        --logaddr "$OUTPUT_RECEIVER_URI" --eventaddr "$event_file" || {
        stop_output_receiver || true
        return 1
    }
    if ! run_openssl_request tls13 "$WORK_DIR/logaddr-${transport}.client.log"; then
        stop_capture
        stop_output_receiver || true
        return 1
    fi
    sleep 1
    stop_capture
    stop_output_receiver || return 1
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "captured text event" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN"
}

case_operational_stdout() {
    local capture_log="$WORK_DIR/logaddr-stdout.ecapture.log"
    local operational_log="$WORK_DIR/logaddr.stdout.log"
    local event_file="$WORK_DIR/logaddr-stdout.events.log"
    start_capture_split "$operational_log" "$capture_log" tls --libssl "$OPENSSL_LIB" \
        --model text --logaddr stdout --eventaddr "$event_file" || return 1
    if ! run_openssl_request tls13 "$WORK_DIR/logaddr-stdout.client.log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "captured text event" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN"
}

case_keylog_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/keylog-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/keylog-${transport}.operational.log"
    local keylog_file="$WORK_DIR/openssl.${transport}.keys.log"
    local packet_file="$WORK_DIR/openssl.${transport}.pcapng"
    local packet_log="$WORK_DIR/openssl.${transport}.tshark-capture.log"
    start_output_receiver "$transport" "$keylog_file" || return 1
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || {
        stop_output_receiver || true
        return 1
    }
    if ! start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model keylog \
        --logaddr "$operational_log" --eventaddr "$OUTPUT_RECEIVER_URI"; then
        stop_packet_capture
        stop_output_receiver || true
        return 1
    fi
    if ! run_openssl_request tls13 "$WORK_DIR/keylog-${transport}.client.log"; then
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
    assert_file_not_contains "$operational_log" "TRAFFIC_SECRET" "TLS secret in operational log" || return 1
    assert_tls_plaintext_preview "$packet_file" "$keylog_file" "$E2E_TOKEN" \
        "linux/tls/keylog-${transport}"
}

case_keylog_stdout() {
    local capture_log="$WORK_DIR/keylog-stdout.ecapture.log"
    local operational_log="$WORK_DIR/keylog-stdout.operational.log"
    local keylog_file="$WORK_DIR/openssl.stdout.keys.log"
    local packet_file="$WORK_DIR/openssl.stdout-keylog.pcapng"
    local packet_log="$WORK_DIR/openssl.stdout-keylog.tshark-capture.log"
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || return 1
    if ! start_capture_split "$keylog_file" "$capture_log" tls --libssl "$OPENSSL_LIB" \
        --model keylog --eventaddr stdout --logaddr "$operational_log"; then
        stop_packet_capture
        return 1
    fi
    if ! run_openssl_request tls13 "$WORK_DIR/keylog-stdout.client.log"; then
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
    assert_tls_plaintext_preview "$packet_file" "$keylog_file" "$E2E_TOKEN" \
        "linux/tls/keylog-stdout"
}

case_pcapng_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/pcapng-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/pcapng-${transport}.operational.log"
    local pcap_file="$WORK_DIR/openssl.${transport}.pcapng"
    start_output_receiver "$transport" "$pcap_file" || return 1
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model pcapng \
        --logaddr "$operational_log" --eventaddr "$OUTPUT_RECEIVER_URI" \
        --ifname lo --keylogfile= "tcp port $TLS_SERVER_PORT" || {
        stop_output_receiver || true
        return 1
    }
    if ! run_openssl_request tls13 "$WORK_DIR/pcapng-${transport}.client.log"; then
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
    assert_pcapng_plaintext_preview "$pcap_file" "$E2E_TOKEN" \
        "linux/tls/pcapng-${transport}"
}

case_pcapng_stdout() {
    local capture_log="$WORK_DIR/pcapng-stdout.ecapture.log"
    local operational_log="$WORK_DIR/pcapng-stdout.operational.log"
    local pcap_file="$WORK_DIR/openssl.stdout.pcapng"
    start_capture_split "$pcap_file" "$capture_log" tls --libssl "$OPENSSL_LIB" \
        --model pcapng --eventaddr stdout --logaddr "$operational_log" \
        --ifname lo --keylogfile= "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_openssl_request tls13 "$WORK_DIR/pcapng-stdout.client.log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$pcap_file" "$E2E_TOKEN" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng_plaintext_preview "$pcap_file" "$E2E_TOKEN" "linux/tls/pcapng-stdout"
}

case_ecaptureq_text() {
    local capture_log="$WORK_DIR/ecaptureq-text.ecapture.log"
    local operational_log="$WORK_DIR/ecaptureq-text.operational.log"
    local event_file="$WORK_DIR/ecaptureq-text.events.log"
    local client_log="$WORK_DIR/ecaptureq-text.client.log"
    local port=$((30000 + RANDOM % 20000))
    local endpoint="ws://127.0.0.1:${port}/"
    "$WORK_DIR/helpers/ecaptureq_assert" --server "$endpoint" --format text \
        --token "$E2E_TOKEN" >"$client_log" 2>&1 &
    local client_pid=$!
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model text \
        --logaddr "$operational_log" --eventaddr "$event_file" --ecaptureq "$endpoint" || {
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    run_openssl_request tls13 "$WORK_DIR/ecaptureq-text.request.log" || {
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
    "$WORK_DIR/helpers/ecaptureq_assert" --server "$endpoint" --format keylog \
        >"$client_log" 2>&1 &
    local client_pid=$!
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model keylog \
        --logaddr "$operational_log" --eventaddr "$keylog_file" --ecaptureq "$endpoint" || {
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    if ! run_openssl_request tls13 "$WORK_DIR/ecaptureq-keylog.request.log"; then
        stop_capture
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    fi
    local client_status=0
    wait "$client_pid" || client_status=$?
    stop_capture
    if ((client_status != 0)); then
        log_error "Strict eCaptureQ keylog receiver failed"
        cat "$client_log" >&2 || true
        return 1
    fi
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$client_log" \
        "PROCESS_LOG=1 EVENT=1 FORMAT=CAPTURE_FORMAT_KEYLOG METADATA=1" \
        "typed eCaptureQ keylog receiver result" || return 1
    assert_keylog "$keylog_file" || return 1
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
    "$WORK_DIR/helpers/ecaptureq_assert" --server "$endpoint" --format pcapng \
        >"$client_log" 2>&1 &
    local client_pid=$!
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model pcapng \
        --logaddr "$operational_log" --eventaddr "$pcap_file" --ecaptureq "$endpoint" \
        --ifname lo --keylogfile= "tcp port $TLS_SERVER_PORT" || {
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    if ! run_openssl_request tls13 "$WORK_DIR/ecaptureq-pcapng.request.log"; then
        stop_capture
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    fi
    local client_status=0
    wait "$client_pid" || client_status=$?
    sleep 2
    stop_capture
    if ((client_status != 0)); then
        log_error "Strict eCaptureQ pcapng receiver failed"
        cat "$client_log" >&2 || true
        return 1
    fi
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$client_log" \
        "PROCESS_LOG=1 EVENT=1 FORMAT=CAPTURE_FORMAT_PCAPNG METADATA=1" \
        "typed eCaptureQ pcapng receiver result" || return 1
    assert_output_isolation "$operational_log" "$pcap_file" "$E2E_TOKEN" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng_plaintext_preview \
        "$pcap_file" "$E2E_TOKEN" "linux/tls/ecaptureq-pcapng"
}

case_pcapng_burst() {
    local capture_log="$WORK_DIR/pcapng-burst.ecapture.log"
    local client_log="$WORK_DIR/pcapng-burst.client.log"
    local pcap_file="$WORK_DIR/openssl-burst.pcapng"
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model pcapng \
        --ifname lo --pcapfile "$pcap_file" --keylogfile= "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_openssl_burst "$client_log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture

    assert_file_contains "$capture_log" "Probe closed" \
        "graceful capture shutdown" || return 1
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_not_contains "$capture_log" "Packet captured:" \
        "per-packet INFO output in pcapng mode" || return 1
    assert_pcapng "$pcap_file" 1024 || return 1
    assert_pcapng_plaintext_preview \
        "$pcap_file" "$E2E_TOKEN" "linux/tls/pcapng-burst"
}

main() {
    setup_linux_suite tls
    build_openssl_client

    run_case "linux/tls/invalid-output-combinations" case_invalid_output_combinations
    mode_enabled text && run_case "linux/tls/text" case_text
    mode_enabled text && run_case "linux/tls/text-stdout" case_text_stdout
    mode_enabled text && run_case "linux/tls/text-tcp" case_text_stream tcp
    mode_enabled text && run_case "linux/tls/text-websocket" case_text_stream ws
    mode_enabled text && run_case "linux/tls/logaddr-stdout" case_operational_stdout
    mode_enabled text && run_case "linux/tls/logaddr-tcp" case_operational_stream tcp
    mode_enabled text && run_case "linux/tls/logaddr-websocket" case_operational_stream ws
    mode_enabled text && run_case "linux/tls/ecaptureq-receiver-text" case_ecaptureq_text
    mode_enabled keylog && run_case "linux/tls/keylog-tls12-tls13" case_keylog
    mode_enabled keylog && run_case "linux/tls/keylog-stdout" case_keylog_stdout
    mode_enabled keylog && run_case "linux/tls/keylog-tcp" case_keylog_stream tcp
    mode_enabled keylog && run_case "linux/tls/keylog-websocket" case_keylog_stream ws
    mode_enabled keylog && run_case "linux/tls/ecaptureq-receiver-keylog" case_ecaptureq_keylog
    mode_enabled pcapng && run_case "linux/tls/pcapng-with-dsb" case_pcapng
    mode_enabled pcapng && run_case "linux/tls/pcapng-tcp" case_pcapng_stream tcp
    mode_enabled pcapng && run_case "linux/tls/pcapng-websocket" case_pcapng_stream ws
    mode_enabled pcapng && run_case "linux/tls/pcapng-stdout" case_pcapng_stdout
    mode_enabled pcapng && run_case "linux/tls/ecaptureq-receiver-pcapng" case_ecaptureq_pcapng
    if mode_enabled pcapng && [[ "${E2E_STRESS:-0}" == "1" ]]; then
        run_case "linux/tls/pcapng-burst-no-drop" case_pcapng_burst
    fi

    print_summary "Linux OpenSSL TLS E2E"
}

main "$@"
