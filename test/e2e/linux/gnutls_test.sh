#!/usr/bin/env bash
# GnuTLS probe E2E tests for Ubuntu 22.04+.

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
    GNUTLS_LIB="$(resolve_linked_library "$GNUTLS_CLIENT" 'libgnutls\.so')"
    log_info "GnuTLS fixture library: $GNUTLS_LIB"
}

run_gnutls_request() {
    local tls_version="$1"
    local output_file="$2"
    timeout 15 "$GNUTLS_CLIENT" 127.0.0.1 "$TLS_SERVER_PORT" /e2e "$E2E_TOKEN" "$tls_version" \
        >"$output_file" 2>&1
    assert_file_contains "$output_file" "$E2E_TOKEN" "GnuTLS fixture response"
}

case_text() {
    local capture_log="$WORK_DIR/text.ecapture.log"
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model text || return 1
    if ! run_gnutls_request tls13 "$WORK_DIR/text.client.log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$capture_log" "$E2E_TOKEN" "captured GnuTLS plaintext" || return 1
    print_plaintext_preview "$capture_log" "$E2E_TOKEN" "linux/gnutls/text"
}

case_keylog() {
    local capture_log="$WORK_DIR/keylog.ecapture.log"
    local keylog_file="$WORK_DIR/gnutls.keys.log"
    local packet_file="$WORK_DIR/gnutls.keylog.pcapng"
    local packet_log="$WORK_DIR/gnutls.keylog.tshark-capture.log"
    start_packet_capture lo "tcp port $TLS_SERVER_PORT" "$packet_file" "$packet_log" || return 1
    if ! start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model keylog --keylogfile "$keylog_file"; then
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
        "$packet_file" "$keylog_file" "$E2E_TOKEN" "linux/gnutls/keylog"
}

case_pcapng() {
    local capture_log="$WORK_DIR/pcapng.ecapture.log"
    local pcap_file="$WORK_DIR/gnutls.pcapng"
    start_capture "$capture_log" gnutls --gnutls "$GNUTLS_LIB" --model pcapng \
        --ifname lo --pcapfile "$pcap_file" --keylogfile= "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_gnutls_request tls13 "$WORK_DIR/pcapng.client.log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_pcapng "$pcap_file" || return 1
    assert_pcapng_plaintext_preview \
        "$pcap_file" "$E2E_TOKEN" "linux/gnutls/pcapng"
}

main() {
    setup_linux_suite gnutls
    build_gnutls_client

    mode_enabled text && run_case "linux/gnutls/text" case_text
    mode_enabled keylog && run_case "linux/gnutls/keylog-tls12-tls13" case_keylog
    mode_enabled pcapng && run_case "linux/gnutls/pcapng-with-dsb" case_pcapng

    print_summary "Linux GnuTLS E2E"
}

main "$@"
