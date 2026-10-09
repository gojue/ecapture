#!/usr/bin/env bash
# GoTLS probe E2E tests for Ubuntu 22.04+.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/linux/common.sh
source "$SCRIPT_DIR/common.sh"

GO_CLIENT=""

build_go_client() {
    GO_CLIENT="$WORK_DIR/helpers/go_https_client"
    CGO_ENABLED=0 go build -o "$GO_CLIENT" "$E2E_DIR/go_https_client.go"
}

run_go_request() {
    local tls_version="$1"
    local output_file="$2"
    local version_flag
    case "$tls_version" in
        tls12) version_flag="1.2" ;;
        tls13) version_flag="1.3" ;;
        *) log_error "Unknown Go TLS fixture version: $tls_version"; return 1 ;;
    esac
    timeout 15 "$GO_CLIENT" --url "$TLS_SERVER_URL" --insecure \
        --tls-version "$version_flag" --expect "$E2E_TOKEN" >"$output_file" 2>&1
    assert_file_contains "$output_file" "$E2E_TOKEN" "Go TLS fixture response"
}

case_invalid_output_combinations() {
    local output="$WORK_DIR/invalid-output.log"
    if "$ECAPTURE_BINARY" gotls --elfpath "$GO_CLIENT" --model keylog \
        --eventaddr "$WORK_DIR/a.keys" --keylogfile "$WORK_DIR/b.keys" >"$output" 2>&1; then
        log_error "conflicting --eventaddr/--keylogfile unexpectedly succeeded"
        return 1
    fi
    assert_file_contains "$output" "cannot both select" "legacy destination conflict" || return 1
    if "$ECAPTURE_BINARY" gotls --elfpath "$GO_CLIENT" --model text \
        --eventaddr udp://127.0.0.1:9000 >"$output" 2>&1; then
        log_error "unsupported event scheme unexpectedly succeeded"
        return 1
    fi
    assert_file_contains "$output" "unsupported sink URI scheme" "unsupported scheme rejection" || return 1
    if "$ECAPTURE_BINARY" gotls --elfpath "$GO_CLIENT" --model pcapng --ifname lo \
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
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text \
        --logaddr "$operational_log" --eventaddr "$event_file" || return 1
    if ! run_go_request tls13 "$WORK_DIR/text.client.log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "captured GoTLS plaintext" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    print_plaintext_preview "$event_file" "$E2E_TOKEN" "linux/gotls/text"
}

case_keylog() {
    local capture_log="$WORK_DIR/keylog.ecapture.log"
    local operational_log="$WORK_DIR/keylog.operational.log"
    local keylog_file="$WORK_DIR/gotls.keys.log"
    local packet_file="$WORK_DIR/gotls.keylog.pcapng"
    local packet_log="$WORK_DIR/gotls.keylog.tshark-capture.log"
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || return 1
    if ! start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model keylog \
        --logaddr "$operational_log" --keylogfile "$keylog_file"; then
        stop_packet_capture
        return 1
    fi
    if ! run_go_request tls12 "$WORK_DIR/keylog.tls12.client.log" || \
       ! run_go_request tls13 "$WORK_DIR/keylog.tls13.client.log"; then
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
        log_error "GoTLS TLS 1.2 CLIENT_RANDOM was not captured"
        return 1
    }
    grep -Eq '^(CLIENT|SERVER)_(HANDSHAKE_)?TRAFFIC_SECRET' "$keylog_file" || {
        log_error "GoTLS TLS 1.3 traffic secret was not captured"
        return 1
    }
    assert_tls_plaintext_preview \
        "$packet_file" "$keylog_file" "$E2E_TOKEN" "linux/gotls/keylog"
}

case_pcapng() {
    local capture_log="$WORK_DIR/pcapng.ecapture.log"
    local operational_log="$WORK_DIR/pcapng.operational.log"
    local pcap_file="$WORK_DIR/gotls.pcapng"
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model pcapng \
        --logaddr "$operational_log" --ifname lo --pcapfile "$pcap_file" \
        --keylogfile= "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_go_request tls13 "$WORK_DIR/pcapng.client.log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$pcap_file" "$E2E_TOKEN" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng_plaintext_preview \
        "$pcap_file" "$E2E_TOKEN" "linux/gotls/pcapng"
}

case_text_tcp() {
    local capture_log="$WORK_DIR/text-tcp.ecapture.log"
    local operational_log="$WORK_DIR/text-tcp.operational.log"
    local event_file="$WORK_DIR/text-tcp.events.log"
    start_output_receiver tcp "$event_file" || return 1
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text \
        --logaddr "$operational_log" --eventaddr "$OUTPUT_RECEIVER_URI" || {
        stop_output_receiver || true
        return 1
    }
    run_go_request tls13 "$WORK_DIR/text-tcp.client.log" || {
        stop_capture
        stop_output_receiver || true
        return 1
    }
    sleep 1
    stop_capture
    stop_output_receiver || return 1
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "TCP text output" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
}

case_keylog_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/keylog-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/keylog-${transport}.operational.log"
    local keylog_file="$WORK_DIR/gotls.${transport}.keys.log"
    local packet_file="$WORK_DIR/gotls.${transport}.pcapng"
    local packet_log="$WORK_DIR/gotls.${transport}.tshark-capture.log"
    start_output_receiver "$transport" "$keylog_file" || return 1
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || {
        stop_output_receiver || true
        return 1
    }
    if ! start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model keylog \
        --logaddr "$operational_log" --eventaddr "$OUTPUT_RECEIVER_URI"; then
        stop_packet_capture
        stop_output_receiver || true
        return 1
    fi
    if ! run_go_request tls13 "$WORK_DIR/keylog-${transport}.client.log"; then
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
        "linux/gotls/keylog-${transport}"
}

case_pcapng_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/pcapng-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/pcapng-${transport}.operational.log"
    local pcap_file="$WORK_DIR/gotls.${transport}.pcapng"
    start_output_receiver "$transport" "$pcap_file" || return 1
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model pcapng \
        --logaddr "$operational_log" --eventaddr "$OUTPUT_RECEIVER_URI" \
        --ifname lo --keylogfile= "tcp port $TLS_SERVER_PORT" || {
        stop_output_receiver || true
        return 1
    }
    if ! run_go_request tls13 "$WORK_DIR/pcapng-${transport}.client.log"; then
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
        "linux/gotls/pcapng-${transport}"
}

case_pcapng_stdout() {
    local capture_log="$WORK_DIR/pcapng-stdout.ecapture.log"
    local operational_log="$WORK_DIR/pcapng-stdout.operational.log"
    local pcap_file="$WORK_DIR/gotls.stdout.pcapng"
    start_capture_split "$pcap_file" "$capture_log" gotls --elfpath "$GO_CLIENT" \
        --model pcapng --eventaddr stdout --logaddr "$operational_log" \
        --ifname lo --keylogfile= "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_go_request tls13 "$WORK_DIR/pcapng-stdout.client.log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$pcap_file" "$E2E_TOKEN" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng_plaintext_preview "$pcap_file" "$E2E_TOKEN" "linux/gotls/pcapng-stdout"
}

case_ecaptureq_text() {
    local capture_log="$WORK_DIR/ecaptureq-text.ecapture.log"
    local event_file="$WORK_DIR/ecaptureq-text.events.log"
    local client_log="$WORK_DIR/ecaptureq-text.client.log"
    local port=$((30000 + RANDOM % 20000))
    local endpoint="ws://127.0.0.1:${port}/"
    "$WORK_DIR/helpers/ecaptureq_assert" --server "$endpoint" --format text \
        --token "$E2E_TOKEN" >"$client_log" 2>&1 &
    local client_pid=$!
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text \
        --eventaddr "$event_file" --ecaptureq "$endpoint" || {
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    run_go_request tls13 "$WORK_DIR/ecaptureq-text.request.log" || {
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
    assert_file_contains "$client_log" "PROCESS_LOG=1 EVENT=1" \
        "typed eCaptureQ dual-channel result" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "additive raw text event" || return 1
}

main() {
    setup_linux_suite gotls
    build_go_client

    run_case "linux/gotls/invalid-output-combinations" case_invalid_output_combinations
    mode_enabled text && run_case "linux/gotls/text" case_text
    mode_enabled text && run_case "linux/gotls/text-tcp" case_text_tcp
    mode_enabled text && run_case "linux/gotls/ecaptureq-text" case_ecaptureq_text
    mode_enabled keylog && run_case "linux/gotls/keylog-tls12-tls13" case_keylog
    mode_enabled keylog && run_case "linux/gotls/keylog-tcp" case_keylog_stream tcp
    mode_enabled keylog && run_case "linux/gotls/keylog-websocket" case_keylog_stream ws
    mode_enabled pcapng && run_case "linux/gotls/pcapng-with-dsb" case_pcapng
    mode_enabled pcapng && run_case "linux/gotls/pcapng-tcp" case_pcapng_stream tcp
    mode_enabled pcapng && run_case "linux/gotls/pcapng-websocket" case_pcapng_stream ws
    mode_enabled pcapng && run_case "linux/gotls/pcapng-stdout" case_pcapng_stdout

    print_summary "Linux GoTLS E2E"
}

main "$@"
