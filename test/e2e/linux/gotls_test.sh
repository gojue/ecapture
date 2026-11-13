#!/usr/bin/env bash
# GoTLS probe E2E tests for supported Ubuntu and Debian hosts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/linux/common.sh
source "$SCRIPT_DIR/common.sh"

GO_CLIENT=""
HTTP_REASSEMBLY_CLIENT=""
HTTP3_FIXTURE=""
TLS_RAW_CLIENT=""

build_go_client() {
    GO_CLIENT="$WORK_DIR/helpers/go_https_client"
    CGO_ENABLED=0 go build -o "$GO_CLIENT" "$E2E_DIR/go_https_client.go"
}

build_http_reassembly_client() {
    HTTP_REASSEMBLY_CLIENT="$WORK_DIR/helpers/http_reassembly_client"
    CGO_ENABLED=0 go build -o "$HTTP_REASSEMBLY_CLIENT" "$E2E_DIR/fixtures/http_reassembly_client/main.go"
}

build_http3_fixture() {
    local tshark_version
    tshark_version="$(tshark --version | awk 'NR == 1 { print $3 }')"
    if [[ ! "$tshark_version" =~ ^([0-9]+)\.([0-9]+)\. ]] ||
        ((BASH_REMATCH[1] < 4 || (BASH_REMATCH[1] == 4 && BASH_REMATCH[2] < 4))); then
        log_error "GoTLS HTTP/3 E2E requires tshark >= 4.4 (found $tshark_version)"
        return 1
    fi
    HTTP3_FIXTURE="$WORK_DIR/helpers/http3"
    (cd "$E2E_DIR/fixtures/http3" && GOWORK=off CGO_ENABLED=0 go build -buildvcs=false -mod=readonly -o "$HTTP3_FIXTURE" .)
}

build_tls_raw_client() {
    TLS_RAW_CLIENT="$WORK_DIR/helpers/tls_raw_client"
    CGO_ENABLED=0 go build -o "$TLS_RAW_CLIENT" "$E2E_DIR/fixtures/tls_raw_client/main.go"
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
    if "$ECAPTURE_BINARY" gotls --elfpath "$GO_CLIENT" --model text --text-source hook \
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
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text --text-source hook \
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
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text \
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

assert_http3_events() {
    # Validate each message in its connection/stream envelope, including the
    # direction and exactly-once delivery. Tokens appear only in body lines.
    awk -v token="$E2E_TOKEN" '
        /^\[/ {
            messages++
            direction = $3
            connection = $0
            sub(/.* connection="/, "", connection)
            sub(/".*/, "", connection)
            stream = $0
            sub(/.* stream=/, "", stream)
            valid = ($2 == "http/3" && connection != "" && stream ~ /^(0|4)$/)
        }
        {
            sub(/\r$/, "")
            for (c = 0; c < 2; c++) {
                for (s = 0; s <= 4; s += 4) {
                    for (d = 0; d < 2; d++) {
                        label = d ? "RESPONSE" : "REQUEST"
                        if ($0 != token "_C" c "_S" s "_" label) continue
                        if (!valid || stream != s || direction != tolower(label)) bad = 1
                        if (connections[c] != "" && connections[c] != connection) bad = 1
                        connections[c] = connection
                        seen[c, s, d]++
                    }
                }
            }
        }
        END {
            for (c = 0; c < 2; c++)
                for (s = 0; s <= 4; s += 4)
                    for (d = 0; d < 2; d++)
                        if (seen[c, s, d] != 1) bad = 1
            if (messages != 8 || connections[0] == connections[1]) bad = 1
            exit bad
        }
    ' "$1" || {
        log_error "HTTP/3 output must contain both directions on streams 0 and 4 of two distinct connections"
        return 1
    }
}

assert_http3_pcapng() {
    local pcap_file="$1" expected_version="$2"
    local connection_file="${pcap_file}.connections"
    local tshark_log="${pcap_file}.tshark.log"
    local connections=() labels=() connection stream direction plaintext marker label candidate
    # No external keylog is accepted: independently decrypt eCapture's DSB.
    if ! tshark -n -r "$pcap_file" -o tls.keylog_file: \
        -Y quic.connection.number -T fields -e quic.connection.number -e quic.version -E occurrence=f \
        >"$connection_file" 2>"$tshark_log"; then
        log_error "tshark could not identify HTTP/3 connections"
        return 1
    fi
    mapfile -t connections < <(cut -f1 "$connection_file" | sort -un | sed '/^$/d')
    if ((${#connections[@]} != 2)); then
        log_error "Expected two QUIC connections in eCapture pcapng"
        return 1
    fi
    for connection in "${connections[@]}"; do
        # Prove the version on the wire for both connections, including the
        # server's long-header packets; fixture flags alone cannot prove it.
        if ! awk -F '\t' -v connection="$connection" -v version="$expected_version" '
            $1 == connection && $2 != "" { seen = 1; if ($2 != version) bad = 1 }
            END { exit !seen || bad }
        ' "$connection_file"; then
            log_error "QUIC connection $connection did not exclusively use version $expected_version"
            return 1
        fi
        label=""
        for stream in 0 4; do
            plaintext="${pcap_file}.connection-${connection}.stream-${stream}.plaintext.txt"
            if ! tshark -n -r "$pcap_file" -o tls.keylog_file: -q \
                -z "follow,quic,ascii,$connection,$stream" \
                >"$plaintext" 2>>"$tshark_log"; then
                log_error "tshark could not decrypt QUIC connection $connection stream $stream from DSB"
                return 1
            fi
            if [[ "$stream" == 0 ]]; then
                # Concurrent handshakes make tshark's connection numbering
                # independent of the fixture's C0/C1 body labels.
                for candidate in 0 1; do
                    if grep -Fq -- "${E2E_TOKEN}_C${candidate}_S0_REQUEST" "$plaintext"; then
                        if [[ -n "$label" ]]; then
                            log_error "QUIC connection $connection contains multiple fixture labels"
                            return 1
                        fi
                        label="$candidate"
                    fi
                done
                if [[ -z "$label" || -n "${labels[$label]:-}" ]]; then
                    log_error "QUIC connection $connection has a missing or repeated fixture label"
                    return 1
                fi
                labels[label]=1
            fi
            for direction in REQUEST RESPONSE; do
                marker="${E2E_TOKEN}_C${label}_S${stream}_${direction}"
                # tshark follow may repeat loopback packet copies. Exactly-once
                # application delivery is checked in assert_http3_events.
                if ! grep -Fq -- "$marker" "$plaintext"; then
                    log_error "DSB plaintext missing C$label stream $stream $direction marker"
                    return 1
                fi
            done
        done
    done
}

case_text_pcapng_http3() {
    local version="$1" expected_version
    case "$version" in
        v1) expected_version="0x00000001" ;;
        v2) expected_version="0x6b3343cf" ;;
        *) log_error "Unknown QUIC fixture version: $version"; return 1 ;;
    esac
    local capture_log="$WORK_DIR/http3-$version.ecapture.log"
    local operational_log="$WORK_DIR/http3-$version.operational.log"
    local event_file="$WORK_DIR/http3-$version.events.log"
    local pcap_file="$WORK_DIR/http3-$version.pcapng"
    local ready_file="$WORK_DIR/http3-$version.addr"
    local address="" attempt connection stream direction

    # Baseline captures one UDP datagram per skb; GSO/GRO coverage is separate.
    QUIC_GO_DISABLE_GSO=true "$HTTP3_FIXTURE" --mode server --ready-file "$ready_file" \
        --quic-version "$version" --token "$E2E_TOKEN" >"$WORK_DIR/http3-$version.server.log" 2>&1 &
    HTTP3_PID=$!
    for attempt in $(seq 1 50); do
        if [[ -s "$ready_file" ]]; then
            address="$(tr -d '\r\n' <"$ready_file")"
            break
        fi
        kill -0 "$HTTP3_PID" 2>/dev/null || break
        sleep 0.1
    done
    if [[ -z "$address" ]]; then
        log_error "HTTP/3 fixture did not become ready"
        return 1
    fi
    start_capture "$capture_log" gotls --elfpath "$HTTP3_FIXTURE" --model text --text-source pcapng \
        --logaddr "$operational_log" --eventaddr "$event_file" --ifname lo \
        --pcapfile "$pcap_file" "udp port ${address##*:}" || return 1
    if ! QUIC_GO_DISABLE_GSO=true timeout 45 "$HTTP3_FIXTURE" --mode client --address "$address" \
        --quic-version "$version" --token "$E2E_TOKEN" >"$WORK_DIR/http3-$version.client.log" 2>&1; then
        stop_capture
        log_error "HTTP/3 fixture client failed"
        return 1
    fi
    for connection in 0 1; do
        for stream in 0 4; do
            for direction in REQUEST RESPONSE; do
                if ! wait_for_file_contains "$event_file" "${E2E_TOKEN}_C${connection}_S${stream}_${direction}" \
                    "live HTTP/3 connection $connection stream $stream $direction"; then
                    stop_capture
                    return 1
                fi
            done
        done
    done
    # Assert the full result while the probe is still running, before EOF flush.
    kill -0 "$CAPTURE_PID" 2>/dev/null || return 1
    assert_http3_events "$event_file" || { stop_capture; return 1; }
    stop_capture
    kill -TERM "$HTTP3_PID" 2>/dev/null || true
    wait "$HTTP3_PID" 2>/dev/null || true
    HTTP3_PID=""
    assert_no_capture_errors "$capture_log" || return 1
    assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
    assert_file_not_contains "$operational_log" "TRAFFIC_SECRET" "TLS secret in operational log" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_http3_pcapng "$pcap_file" "$expected_version"
}

case_text_pcapng_protocol() (
    local protocol="$1" version="${2:-v1}" transport=tcp streaming=0
    local prefix="$WORK_DIR/protocol-${protocol}-${version}"
    local capture_log="${prefix}.ecapture.log" operational_log="${prefix}.operational.log"
    local event_file="${prefix}.events.log" pcap_file="${prefix}.pcapng"
    local ready_file="${prefix}.addr" release_file="${prefix}.release"
    local server_pid="" client_pid="" fixture_pid="" address="" attempt verified=0 token_hex
    local options=()
    trap '
        stop_capture || true
        for fixture_pid in "$client_pid" "$server_pid"; do
            if [[ -n "$fixture_pid" ]]; then
                kill -TERM "$fixture_pid" 2>/dev/null || true
                wait "$fixture_pid" 2>/dev/null || true
            fi
        done
    ' EXIT
    case "$protocol" in
        dot|mqtt|redis|doq) options+=(--text-protocol "$protocol") ;;
        doh*) options+=(--text-protocol doh) ;;
        smtp|connect|https-connect) options+=(--text-tls-upgrade "$protocol" --text-raw) ;;
        websocket) ;;
        datagram) options+=(--text-raw) ;;
        sse*|grpc) options+=(--text-http-events); streaming=1 ;;
        *) log_error "Unknown protocol fixture $protocol"; return 1 ;;
    esac
    [[ "$protocol" != sse-gzip ]] || options+=(--text-max-decoded-body 1048576)
    case "$protocol" in doh3|sse3|doq|datagram) transport=udp ;; esac
    QUIC_GO_DISABLE_GSO=true "$HTTP3_FIXTURE" --mode server --protocol "$protocol" \
        --ready-file "$ready_file" --release-file "$release_file" --token "$E2E_TOKEN" \
        --quic-version "$version" >"${prefix}.server.log" 2>&1 &
    server_pid=$!
    for attempt in $(seq 1 50); do
        if [[ -s "$ready_file" ]]; then
            address="$(cat "$ready_file")"
            break
        fi
        kill -0 "$server_pid" 2>/dev/null || break
        sleep 0.1
    done
    if [[ -z "$address" ]]; then
        log_error "$protocol fixture did not become ready"
        return 1
    fi
    start_capture "$capture_log" gotls --elfpath "$HTTP3_FIXTURE" --model text --text-source pcapng \
        --eventaddr "$event_file" --logaddr "$operational_log" --ifname lo --pcapfile "$pcap_file" \
        "${options[@]}" "$transport port ${address##*:}" || return 1
    QUIC_GO_DISABLE_GSO=true timeout 30 "$HTTP3_FIXTURE" --mode client --protocol "$protocol" \
        --address "$address" --token "$E2E_TOKEN" --quic-version "$version" >"${prefix}.client.log" 2>&1 &
    client_pid=$!
    if ((streaming)); then
        for attempt in $(seq 1 60); do
            if "$HTTP3_FIXTURE" --mode verify --protocol "$protocol" --events-file "$event_file" \
                --token "$E2E_TOKEN" --phase live >"${prefix}.verify.log" 2>&1; then
                verified=1
                break
            fi
            sleep 0.1
        done
        if ((verified == 0)) || ! kill -0 "$client_pid" 2>/dev/null || ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            log_error "$protocol semantic events did not arrive while the response remained open"
            cat "${prefix}.verify.log" >&2
            return 1
        fi
        touch "$release_file"
    fi
    if ! wait "$client_pid"; then
        client_pid=""
        log_error "$protocol fixture client failed"
        cat "${prefix}.client.log" >&2
        return 1
    fi
    client_pid=""
    verified=0
    for attempt in $(seq 1 60); do
        if "$HTTP3_FIXTURE" --mode verify --protocol "$protocol" --events-file "$event_file" \
            --token "$E2E_TOKEN" >"${prefix}.verify.log" 2>&1; then
            verified=1
            break
        fi
        sleep 0.1
    done
    if ((verified == 0)) || ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
        log_error "$protocol exact bytes/metadata did not arrive before capture shutdown"
        cat "${prefix}.verify.log" >&2
        return 1
    fi
    stop_capture
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_not_contains "$operational_log" "$E2E_TOKEN" "plaintext in operational log" || return 1
    token_hex="$(printf '%s' "$E2E_TOKEN" | od -An -tx1 | tr -d ' \n')"
    assert_file_not_contains "$operational_log" "$token_hex" "hex plaintext in operational log" || return 1
    assert_file_not_contains "$operational_log" "TRAFFIC_SECRET" "TLS secret in operational log" || return 1
    assert_pcapng "$pcap_file" || return 1
    if [[ "$transport" == udp ]]; then
        local expected_version=0x00000001
        [[ "$version" != v2 ]] || expected_version=0x6b3343cf
        tshark -n -r "$pcap_file" -o tls.keylog_file: -Y quic.version -T fields -e quic.version \
            -E occurrence=f >"${prefix}.versions" 2>"${prefix}.tshark.log" || return 1
        awk -v version="$expected_version" 'NF { seen=1; if ($0 != version) bad=1 } END { exit !seen || bad }' \
            "${prefix}.versions" || { log_error "$protocol wire QUIC version mismatch"; return 1; }
        if [[ "$protocol" == doq || "$protocol" == datagram ]]; then
            tshark -n -r "$pcap_file" -o tls.keylog_file: -Y "udp.dstport == ${address##*:} && quic.scid" \
                -T fields -e quic.scid -E occurrence=f >"${prefix}.client-cids" 2>>"${prefix}.tshark.log" || return 1
            awk 'NF { gsub(/:/, ""); seen=1; if (length != 16) bad=1 } END { exit !seen || bad }' \
                "${prefix}.client-cids" || { log_error "$protocol requires eight-byte client CIDs on the wire"; return 1; }
        fi
    fi
)

assert_tls_raw_events() {
    local file="$1" client_hex="$2" server_hex="$3" require_end="${4:-0}"
    [[ -s "$file" ]] || return 1
    awk -v client="$client_hex" -v server="$server_hex" -v require_end="$require_end" '
        /^\[/ {
            direction = $3
            if ($2 != "tls" || (direction != "client_to_server" && direction != "server_to_client")) bad = 1
            connection = $0
            sub(/.* connection="/, "", connection)
            sub(/".*/, "", connection)
            if (connection == "" || (identity != "" && identity != connection)) bad = 1
            identity = connection
            kind = offset = end = size = encoding = ""
            for (i = 7; i <= NF; i++) {
                split($i, field, "=")
                if (field[1] == "kind") kind = field[2]
                if (field[1] == "offset") offset = field[2]
                if (field[1] == "end") end = field[2]
                if (field[1] == "length") size = field[2]
                if (field[1] == "encoding") encoding = field[2]
            }
            if ((getline hex) <= 0) { bad = 1; next }
            if (encoding != "hex" || hex !~ /^[0-9a-f]*$/ || size !~ /^[0-9]+$/ ||
                offset !~ /^[0-9]+$/ || length(hex) != size * 2 ||
                offset != length(data[direction]) / 2 || ended[direction]) bad = 1
            if (kind == "stream_end" && end == "true" && size == 0) ended[direction]++
            else if (kind != "stream_chunk" || end != "false" || size == 0) bad = 1
            data[direction] = data[direction] hex
        }
        END {
            if (data["client_to_server"] != client || data["server_to_client"] != server) bad = 1
            if (require_end && (ended["client_to_server"] != 1 || ended["server_to_client"] != 1)) bad = 1
            exit bad
        }
    ' "$file"
}

case_text_pcapng_raw() (
    local destination="$1"
    local prefix="$WORK_DIR/raw-${destination}"
    local capture_log="${prefix}.ecapture.log" operational_log="${prefix}.operational.log"
    local event_file="${prefix}.events.log" ready_file="${prefix}.addr"
    local event_addr="$event_file" address="" attempt live=0
    local client_hex server_hex token_hex receiver_pid="" receiver_status=0 server_pid=""
    local capture_options=()
    trap '
        stop_capture || true
        stop_output_receiver || true
        if [[ -n "$receiver_pid" ]]; then
            kill -TERM "$receiver_pid" 2>/dev/null || true
            wait "$receiver_pid" 2>/dev/null || true
        fi
        if [[ -n "$server_pid" ]]; then
            kill -TERM "$server_pid" 2>/dev/null || true
            wait "$server_pid" 2>/dev/null || true
        fi
    ' EXIT
    client_hex="$(printf '\000\377%s_CLIENT\n' "$E2E_TOKEN" | od -An -tx1 | tr -d ' \n')"
    server_hex="$(printf '\000\377%s_SERVER\n\177' "$E2E_TOKEN" | od -An -tx1 | tr -d ' \n')"
    token_hex="$(printf '%s' "$E2E_TOKEN" | od -An -tx1 | tr -d ' \n')"

    "$WORK_DIR/helpers/tls_server" --raw --listen 127.0.0.1:0 --ready-file "$ready_file" \
        --token "$E2E_TOKEN" >"${prefix}.server.log" 2>&1 &
    server_pid=$!
    for attempt in $(seq 1 50); do
        if [[ -s "$ready_file" ]]; then
            address="$(tr -d '\r\n' <"$ready_file")"
            break
        fi
        kill -0 "$server_pid" 2>/dev/null || break
        sleep 0.1
    done
    if [[ -z "$address" ]]; then
        log_error "Binary TLS fixture did not become ready"
        return 1
    fi
    case "$destination" in
        tcp|ws)
            start_output_receiver "$destination" "$event_file" || return 1
            event_addr="$OUTPUT_RECEIVER_URI"
            ;;
        ecaptureq)
            local port=$((30000 + RANDOM % 20000))
            local endpoint="ws://127.0.0.1:${port}/"
            "$WORK_DIR/helpers/ecaptureq_assert" --server "$endpoint" --format text \
                --sensitive --token "$token_hex" >"${prefix}.receiver.log" 2>&1 &
            receiver_pid=$!
            capture_options+=(--ecaptureq "$endpoint")
            ;;
    esac
    if [[ "$destination" != messages ]]; then
        capture_options+=(--text-raw)
    fi
    if [[ "$destination" == stdout ]]; then
        start_capture_split "$event_file" "$capture_log" gotls --elfpath "$TLS_RAW_CLIENT" \
            --model text --text-source pcapng --eventaddr stdout --logaddr "$operational_log" \
            --ifname lo "${capture_options[@]}" "tcp port ${address##*:}" || return 1
    else
        start_capture "$capture_log" gotls --elfpath "$TLS_RAW_CLIENT" --model text --text-source pcapng \
            --eventaddr "$event_addr" --logaddr "$operational_log" --ifname lo \
            "${capture_options[@]}" "tcp port ${address##*:}" || return 1
    fi
    if ! timeout 15 "$TLS_RAW_CLIENT" --address "$address" --token "$E2E_TOKEN" >"${prefix}.client.log" 2>&1; then
        stop_capture
        log_error "Binary TLS fixture client failed"
        return 1
    fi
    if [[ "$destination" == messages ]]; then
        wait_for_file_contains "$operational_log" unsupported_protocol "non-HTTP protocol diagnostic" || {
            stop_capture
            return 1
        }
    else
        for ((attempt = 0; attempt < 40; attempt++)); do
            if assert_tls_raw_events "$event_file" "$client_hex" "$server_hex"; then
                live=1
                break
            fi
            sleep 0.1
        done
        if ((live == 0)) || ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            stop_capture
            log_error "Exact bidirectional binary bytes did not arrive before capture shutdown"
            return 1
        fi
    fi
    if [[ -n "$receiver_pid" ]]; then
        wait "$receiver_pid" || receiver_status=$?
        receiver_pid=""
    fi
    stop_capture
    if [[ "$destination" == tcp || "$destination" == ws ]]; then
        stop_output_receiver || return 1
    fi
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
    assert_no_capture_errors "$capture_log" || return 1
    assert_file_not_contains "$operational_log" "$token_hex" "hex plaintext in operational log" || return 1
    assert_file_not_contains "$operational_log" "TRAFFIC_SECRET" "TLS secret in operational log" || return 1
    if [[ "$destination" == messages ]]; then
        assert_file_contains "$operational_log" "Probe closed" "clean message-mode shutdown" || return 1
        assert_file_not_contains "$operational_log" "$E2E_TOKEN" "binary payload in operational log" || return 1
        if [[ -s "$event_file" ]]; then
            log_error "Default message mode emitted a false application message for binary TLS"
            return 1
        fi
    else
        assert_output_isolation "$operational_log" "$event_file" "$E2E_TOKEN" || return 1
        assert_tls_raw_events "$event_file" "$client_hex" "$server_hex" 1 || {
            log_error "Binary raw bytes, offsets or input-end records are incorrect"
            return 1
        }
        if ((receiver_status != 0)); then
            log_error "Strict eCaptureQ raw receiver failed"
            return 1
        fi
    fi
)

case_text_stream() {
    local transport="$1"
    local capture_log="$WORK_DIR/text-${transport}.ecapture.log"
    local operational_log="$WORK_DIR/text-${transport}.operational.log"
    local event_file="$WORK_DIR/text-${transport}.events.log"
    start_output_receiver "$transport" "$event_file" || return 1
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text --text-source hook \
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
        --model text --text-source hook --eventaddr stdout --logaddr "$operational_log" || return 1
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
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text --text-source hook \
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
        --model text --text-source hook --logaddr stdout --eventaddr "$event_file" || return 1
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
    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text --text-source hook \
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

    start_capture "$capture_log" gotls --elfpath "$GO_CLIENT" --model text --text-source hook \
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

    printf '{"elf_path":"%s","capture_mode":"text","text_source":"hook"}\n' "$GO_CLIENT" >"$request_body"
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

    printf '{"elf_path":"%s","capture_mode":"text","text_source":"hook","event_collector_addr":"%s"}\n' \
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

    printf '{"elf_path":"%s","capture_mode":"text","text_source":"hook","event_collector_addr":"udp://127.0.0.1:9"}\n' \
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
    if mode_enabled text; then
        build_http3_fixture
        build_tls_raw_client
    fi

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
    mode_enabled text && run_case "linux/gotls/text-pcapng-http-default-source" case_text_pcapng
    mode_enabled text && run_case "linux/gotls/text-pcapng-multi-chunk-http1" case_text_pcapng_multi_chunk_http1
    mode_enabled text && run_case "linux/gotls/text-pcapng-http2-keepalive" case_text_pcapng_http2_keepalive
    if mode_enabled text; then
        local quic_version
        for quic_version in v1 v2; do
            run_case "linux/gotls/text-pcapng-http3-${quic_version}" case_text_pcapng_http3 "$quic_version"
        done
        local raw_destination
        for raw_destination in file stdout tcp ws ecaptureq messages; do
            run_case "linux/gotls/text-pcapng-raw-${raw_destination}" case_text_pcapng_raw "$raw_destination"
        done
        local protocol
        for protocol in dot mqtt redis smtp connect https-connect websocket doh1 doh2 sse1 sse2 sse-gzip grpc; do
            run_case "linux/gotls/text-pcapng-${protocol}" case_text_pcapng_protocol "$protocol"
        done
        for quic_version in v1 v2; do
            for protocol in doh3 doq datagram sse3; do
                run_case "linux/gotls/text-pcapng-${protocol}-${quic_version}" case_text_pcapng_protocol "$protocol" "$quic_version"
            done
        done
    fi

    print_summary "Linux GoTLS E2E"
}

main "$@"
