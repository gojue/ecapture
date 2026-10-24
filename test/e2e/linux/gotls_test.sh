#!/usr/bin/env bash
# GoTLS probe E2E tests for Ubuntu 22.04+.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/linux/common.sh
source "$SCRIPT_DIR/common.sh"

GO_CLIENT=""
HTTP_REASSEMBLY_CLIENT=""

build_go_client() {
    GO_CLIENT="$WORK_DIR/helpers/go_https_client"
    CGO_ENABLED=0 go build -o "$GO_CLIENT" "$E2E_DIR/go_https_client.go"
}

build_http_reassembly_client() {
    HTTP_REASSEMBLY_CLIENT="$WORK_DIR/helpers/http_reassembly_client"
    CGO_ENABLED=0 go build -o "$HTTP_REASSEMBLY_CLIENT" "$E2E_DIR/http_reassembly_client.go"
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

case_text_pcapng() {
    local capture_log="$WORK_DIR/decrypt.ecapture.log"
    local operational_log="$WORK_DIR/decrypt.operational.log"
    local event_file="$WORK_DIR/decrypt.events.log"
    local pcap_file="$WORK_DIR/decrypt.pcapng"
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text --text-source pcapng \
        --logaddr "$operational_log" --eventaddr "$event_file" --ifname lo \
        --pcapfile "$pcap_file" "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_go_request tls13 "$WORK_DIR/decrypt.client.log"; then
        stop_capture
        return 1
    fi
    if ! wait_for_file_contains "$event_file" "$E2E_TOKEN" "live decrypted HTTP response"; then
        stop_capture
        return 1
    fi
    if ! run_go_request tls12 "$WORK_DIR/decrypt.tls12.client.log"; then
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
    assert_http_event_timestamps_current "$event_file" "linux/gotls/text-pcapng" || return 1
    assert_pcapng_plaintext_preview "$pcap_file" "$E2E_TOKEN" "linux/gotls/text-pcapng" || return 1
}

case_text_pcapng_multi_chunk_http1() {
    local chunk_size=8192
    local chunk_count=6
    local capture_log="$WORK_DIR/reassembly-h1.ecapture.log"
    local operational_log="$WORK_DIR/reassembly-h1.operational.log"
    local event_file="$WORK_DIR/reassembly-h1.events.log"
    local pcap_file="$WORK_DIR/reassembly-h1.pcapng"
    local client_log="$WORK_DIR/reassembly-h1.client.log"
    local request_body="$WORK_DIR/reassembly-h1.request.body"

    start_http_reassembly_fixture false || return 1
    start_capture "$capture_log" gotls --elfpath "$HTTP_REASSEMBLY_CLIENT" --model text \
        --text-source pcapng --logaddr "$operational_log" --eventaddr "$event_file" \
        --ifname lo --pcapfile "$pcap_file" "tcp port $HTTP_REASSEMBLY_PORT" || {
        stop_http_reassembly_fixture
        return 1
    }

    if ! timeout 30 "$HTTP_REASSEMBLY_CLIENT" --url "$HTTP_REASSEMBLY_URL/echo" --insecure \
        --tls-version 1.3 --token "$E2E_TOKEN" --chunk-size "$chunk_size" --chunk-count "$chunk_count" \
        --out-request-body "$request_body" >"$client_log" 2>&1; then
        log_error "HTTP/1.1 multi-chunk client failed"
        cat "$client_log" >&2 || true
        stop_capture
        stop_http_reassembly_fixture
        return 1
    fi
    if ! wait_for_file_contains "$event_file" "$E2E_TOKEN" "live decrypted HTTP/1.1 body"; then
        stop_capture
        stop_http_reassembly_fixture
        return 1
    fi
    sleep 2
    stop_capture
    stop_http_reassembly_fixture

    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "decrypted HTTP/1.1 body" || return 1
    grep -Eq 'http/1\.1 request .*host="[^"]+"' "$event_file" || return 1
    grep -Eq 'http/1\.1 response .*host="[^"]+"' "$event_file" || return 1
    assert_chunks_in_order "$event_file" "$E2E_TOKEN" "$chunk_count" "HTTP/1.1 reassembled body" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    assert_file_not_contains "$operational_log" "CLIENT_RANDOM " "TLS secret in operational log" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_http_event_timestamps_current "$event_file" "linux/gotls/text-pcapng-multi-chunk-http1" || return 1
}

case_text_pcapng_http2_keepalive() {
    local chunk_size=8192
    local chunk_count=6
    local request_count=3
    local capture_log="$WORK_DIR/reassembly-h2.ecapture.log"
    local operational_log="$WORK_DIR/reassembly-h2.operational.log"
    local event_file="$WORK_DIR/reassembly-h2.events.log"
    local pcap_file="$WORK_DIR/reassembly-h2.pcapng"
    local client_log="$WORK_DIR/reassembly-h2.client.log"
    local request_body="$WORK_DIR/reassembly-h2.request.body"
    local i

    start_http_reassembly_fixture true || return 1
    start_capture "$capture_log" gotls --elfpath "$HTTP_REASSEMBLY_CLIENT" --model text \
        --text-source pcapng --logaddr "$operational_log" --eventaddr "$event_file" \
        --ifname lo --pcapfile "$pcap_file" "tcp port $HTTP_REASSEMBLY_PORT" || {
        stop_http_reassembly_fixture
        return 1
    }

    if ! timeout 60 "$HTTP_REASSEMBLY_CLIENT" --url "$HTTP_REASSEMBLY_URL/echo" --insecure --h2 \
        --tls-version 1.3 --token "$E2E_TOKEN" --chunk-size "$chunk_size" --chunk-count "$chunk_count" \
        --requests "$request_count" --out-request-body "$request_body" >"$client_log" 2>&1; then
        log_error "HTTP/2 keep-alive client failed"
        cat "$client_log" >&2 || true
        stop_capture
        stop_http_reassembly_fixture
        return 1
    fi
    if ! wait_for_file_contains "$event_file" "$E2E_TOKEN" "live decrypted HTTP/2 body"; then
        stop_capture
        stop_http_reassembly_fixture
        return 1
    fi
    sleep 2
    stop_capture
    stop_http_reassembly_fixture

    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "decrypted HTTP/2 body" || return 1
    grep -Eq 'http/2 request .*host="[^"]+"' "$event_file" || return 1
    grep -Eq 'http/2 response .*host="[^"]+"' "$event_file" || return 1
    for ((i = 0; i < request_count; i++)); do
        if ! grep -Fq -- "/echo?req=$i " "$event_file"; then
            log_error "HTTP/2 keep-alive request $i not captured"
            return 1
        fi
    done
    assert_chunks_in_order "$event_file" "$E2E_TOKEN" "$chunk_count" "HTTP/2 reassembled body" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    assert_file_not_contains "$operational_log" "CLIENT_RANDOM " "TLS secret in operational log" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_http_event_timestamps_current "$event_file" "linux/gotls/text-pcapng-http2-keepalive" || return 1
}

case_text_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/text-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/text-${transport}.operational.log"
    local event_file="$WORK_DIR/text-${transport}.events.log"
    start_output_receiver "$transport" "$event_file" || return 1
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text \
        --logaddr "$operational_log" --eventaddr "$OUTPUT_RECEIVER_URI" || {
        stop_output_receiver || true
        return 1
    }
    run_go_request tls13 "$WORK_DIR/text-${transport}.client.log" || {
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
    print_plaintext_preview "$event_file" "$E2E_TOKEN" "linux/gotls/text-${transport}"
}

case_text_stdout() {
    local capture_log="$WORK_DIR/text-stdout.ecapture.log"
    local operational_log="$WORK_DIR/text-stdout.operational.log"
    local event_file="$WORK_DIR/text.stdout.events.log"
    start_capture_split "$event_file" "$capture_log" gotls --elfpath "$GO_CLIENT" \
        --model text --eventaddr stdout --logaddr "$operational_log" || return 1
    if ! run_go_request tls13 "$WORK_DIR/text-stdout.client.log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$event_file" "$E2E_TOKEN" "stdout text output" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    print_plaintext_preview "$event_file" "$E2E_TOKEN" "linux/gotls/text-stdout"
}

case_operational_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/logaddr-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/logaddr-${transport}.operational.log"
    local event_file="$WORK_DIR/logaddr-${transport}.events.log"
    start_output_receiver "$transport" "$operational_log" || return 1
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text \
        --logaddr "$OUTPUT_RECEIVER_URI" --eventaddr "$event_file" || {
        stop_output_receiver || true
        return 1
    }
    if ! run_go_request tls13 "$WORK_DIR/logaddr-${transport}.client.log"; then
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
    start_capture_split "$operational_log" "$capture_log" gotls --elfpath "$GO_CLIENT" \
        --model text --logaddr stdout --eventaddr "$event_file" || return 1
    if ! run_go_request tls13 "$WORK_DIR/logaddr-stdout.client.log"; then
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

case_keylog_stdout() {
    local capture_log="$WORK_DIR/keylog-stdout.ecapture.log"
    local operational_log="$WORK_DIR/keylog-stdout.operational.log"
    local keylog_file="$WORK_DIR/gotls.stdout.keys.log"
    local packet_file="$WORK_DIR/gotls.stdout-keylog.pcapng"
    local packet_log="$WORK_DIR/gotls.stdout-keylog.tshark-capture.log"
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || return 1
    if ! start_capture_split "$keylog_file" "$capture_log" gotls --elfpath "$GO_CLIENT" \
        --model keylog --eventaddr stdout --logaddr "$operational_log"; then
        stop_packet_capture
        return 1
    fi
    if ! run_go_request tls13 "$WORK_DIR/keylog-stdout.client.log"; then
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
        "linux/gotls/keylog-stdout"
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
    local operational_log="$WORK_DIR/ecaptureq-text.operational.log"
    local event_file="$WORK_DIR/ecaptureq-text.events.log"
    local client_log="$WORK_DIR/ecaptureq-text.client.log"
    local port=$((30000 + RANDOM % 20000))
    local endpoint="ws://127.0.0.1:${port}/"
    "$WORK_DIR/helpers/ecaptureq_assert" --server "$endpoint" --format text \
        --token "$E2E_TOKEN" >"$client_log" 2>&1 &
    local client_pid=$!
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text \
        --logaddr "$operational_log" --eventaddr "$event_file" --ecaptureq "$endpoint" || {
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
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model keylog \
        --logaddr "$operational_log" --eventaddr "$keylog_file" --ecaptureq "$endpoint" || {
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    if ! run_go_request tls13 "$WORK_DIR/ecaptureq-keylog.request.log"; then
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
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model pcapng \
        --logaddr "$operational_log" --eventaddr "$pcap_file" --ecaptureq "$endpoint" \
        --ifname lo --keylogfile= "tcp port $TLS_SERVER_PORT" || {
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
        return 1
    }
    if ! run_go_request tls13 "$WORK_DIR/ecaptureq-pcapng.request.log"; then
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
        "$pcap_file" "$E2E_TOKEN" "linux/gotls/ecaptureq-pcapng"
}

case_text_reload_output() {
    local capture_log="$WORK_DIR/reload.ecapture.log"
    local operational_log="$WORK_DIR/reload.operational.log"
    local original_events="$WORK_DIR/reload-original.events.log"
    local updated_events="$WORK_DIR/reload-updated.events.log"
    local port=$((30000 + RANDOM % 20000))
    local endpoint="http://127.0.0.1:$port/gotls"
    local before_token="$E2E_TOKEN"_RELOAD_BEFORE
    local inherited_token="$E2E_TOKEN"_RELOAD_INHERITED
    local updated_token="$E2E_TOKEN"_RELOAD_UPDATED
    local rejected_token="$E2E_TOKEN"_RELOAD_REJECTED
    local request_body="$WORK_DIR/reload-request.json"
    local response_body="$WORK_DIR/reload-response.json"

    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text \
        --listen "127.0.0.1:$port" \
        --logaddr "$operational_log" --eventaddr "$original_events" \
        --eventroratesize 64 --eventroratetime 3600 || return 1

    timeout 15 "$GO_CLIENT" --url "$TLS_SERVER_URL?marker=$before_token" --insecure \
        --tls-version 1.3 --expect "$E2E_TOKEN" \
        >"$WORK_DIR/reload-before.client.log" 2>&1 || {
        stop_capture
        return 1
    }
    sleep 1
    assert_file_contains "$original_events" "$before_token" \
        "GoTLS event before reload" || {
        stop_capture
        return 1
    }

    printf '{"elf_path":"%s","capture_mode":"text"}\n' "$GO_CLIENT" >"$request_body"
    post_config_update "$endpoint" "$request_body" "$response_body" 1 || {
        stop_capture
        return 1
    }
    timeout 15 "$GO_CLIENT" --url "$TLS_SERVER_URL?marker=$inherited_token" --insecure \
        --tls-version 1.3 --expect "$E2E_TOKEN" \
        >"$WORK_DIR/reload-inherited.client.log" 2>&1 || {
        stop_capture
        return 1
    }
    sleep 1
    assert_file_contains "$original_events" "$inherited_token" \
        "GoTLS inherited event destination" || {
        stop_capture
        return 1
    }

    printf '{"elf_path":"%s","capture_mode":"text","event_collector_addr":"%s"}\n' \
        "$GO_CLIENT" "$updated_events" >"$request_body"
    post_config_update "$endpoint" "$request_body" "$response_body" 1 || {
        stop_capture
        return 1
    }
    timeout 15 "$GO_CLIENT" --url "$TLS_SERVER_URL?marker=$updated_token" --insecure \
        --tls-version 1.3 --expect "$E2E_TOKEN" \
        >"$WORK_DIR/reload-updated.client.log" 2>&1 || {
        stop_capture
        return 1
    }
    sleep 1
    assert_file_contains "$updated_events" "$updated_token" \
        "GoTLS explicitly updated event destination" || {
        stop_capture
        return 1
    }
    assert_file_not_contains "$original_events" "$updated_token" \
        "GoTLS event written to retired destination" || {
        stop_capture
        return 1
    }

    printf '{"elf_path":"%s","capture_mode":"text","event_collector_addr":"udp://127.0.0.1:9"}\n' \
        "$GO_CLIENT" >"$request_body"
    post_config_update "$endpoint" "$request_body" "$response_body" 0 || {
        stop_capture
        return 1
    }
    timeout 15 "$GO_CLIENT" --url "$TLS_SERVER_URL?marker=$rejected_token" --insecure \
        --tls-version 1.3 --expect "$E2E_TOKEN" \
        >"$WORK_DIR/reload-rejected.client.log" 2>&1 || {
        stop_capture
        return 1
    }
    sleep 1
    stop_capture

    assert_file_contains "$updated_events" "$rejected_token" \
        "GoTLS output after rejected reload" || return 1
    assert_file_not_contains "$operational_log" "$before_token" \
        "GoTLS captured payload in operational log" || return 1
    assert_file_not_contains "$operational_log" "$inherited_token" \
        "GoTLS inherited payload in operational log" || return 1
    assert_file_not_contains "$operational_log" "$updated_token" \
        "GoTLS updated payload in operational log" || return 1
    assert_file_not_contains "$operational_log" "$rejected_token" \
        "GoTLS post-rejection payload in operational log" || return 1
    assert_output_isolation "$operational_log" "$original_events" "$before_token" || return 1
    assert_no_capture_errors "$capture_log"
}

main() {
    setup_linux_suite gotls
    build_go_client
    build_http_reassembly_client

    run_case "linux/gotls/invalid-output-combinations" case_invalid_output_combinations
    mode_enabled text && run_case "linux/gotls/text" case_text
    mode_enabled text && run_case "linux/gotls/text-reload-output" case_text_reload_output
    mode_enabled text && run_case "linux/gotls/text-stdout" case_text_stdout
    mode_enabled text && run_case "linux/gotls/text-tcp" case_text_stream tcp
    mode_enabled text && run_case "linux/gotls/text-websocket" case_text_stream ws
    mode_enabled text && run_case "linux/gotls/logaddr-stdout" case_operational_stdout
    mode_enabled text && run_case "linux/gotls/logaddr-tcp" case_operational_stream tcp
    mode_enabled text && run_case "linux/gotls/logaddr-websocket" case_operational_stream ws
    mode_enabled text && run_case "linux/gotls/ecaptureq-receiver-text" case_ecaptureq_text
    mode_enabled keylog && run_case "linux/gotls/keylog-tls12-tls13" case_keylog
    mode_enabled keylog && run_case "linux/gotls/keylog-stdout" case_keylog_stdout
    mode_enabled keylog && run_case "linux/gotls/keylog-tcp" case_keylog_stream tcp
    mode_enabled keylog && run_case "linux/gotls/keylog-websocket" case_keylog_stream ws
    mode_enabled keylog && run_case "linux/gotls/ecaptureq-receiver-keylog" case_ecaptureq_keylog
    mode_enabled pcapng && run_case "linux/gotls/pcapng-with-dsb" case_pcapng
    mode_enabled pcapng && run_case "linux/gotls/pcapng-tcp" case_pcapng_stream tcp
    mode_enabled pcapng && run_case "linux/gotls/pcapng-websocket" case_pcapng_stream ws
    mode_enabled pcapng && run_case "linux/gotls/pcapng-stdout" case_pcapng_stdout
    mode_enabled pcapng && run_case "linux/gotls/ecaptureq-receiver-pcapng" case_ecaptureq_pcapng
    mode_enabled text && run_case "linux/gotls/text-pcapng-http" case_text_pcapng
    mode_enabled text && run_case "linux/gotls/text-pcapng-multi-chunk-http1" case_text_pcapng_multi_chunk_http1
    mode_enabled text && run_case "linux/gotls/text-pcapng-http2-keepalive" case_text_pcapng_http2_keepalive

    print_summary "Linux GoTLS E2E"
}

main "$@"
