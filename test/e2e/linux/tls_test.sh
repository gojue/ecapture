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
    OPENSSL_LIB="$(resolve_linked_library "$OPENSSL_CLIENT" 'libssl\.so')"
    log_info "OpenSSL fixture library: $OPENSSL_LIB"
}

run_openssl_request() {
    local tls_version="$1"
    local output_file="$2"
    timeout 15 "$OPENSSL_CLIENT" 127.0.0.1 "$TLS_SERVER_PORT" /e2e "$E2E_TOKEN" "$tls_version" \
        >"$output_file" 2>&1
    assert_file_contains "$output_file" "$E2E_TOKEN" "OpenSSL fixture response"
}

case_text() {
    local capture_log="$WORK_DIR/text.ecapture.log"
    local client_log="$WORK_DIR/text.client.log"
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model text || return 1
    if ! run_openssl_request tls13 "$client_log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_file_contains "$capture_log" "$E2E_TOKEN" "captured OpenSSL plaintext" || return 1
}

case_keylog() {
    local capture_log="$WORK_DIR/keylog.ecapture.log"
    local keylog_file="$WORK_DIR/openssl.keys.log"
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model keylog --keylogfile "$keylog_file" || return 1
    if ! run_openssl_request tls12 "$WORK_DIR/keylog.tls12.client.log" || \
       ! run_openssl_request tls13 "$WORK_DIR/keylog.tls13.client.log"; then
        stop_capture
        return 1
    fi
    sleep 1
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_keylog "$keylog_file" || return 1
    grep -Eq '^CLIENT_RANDOM ' "$keylog_file" || {
        log_error "OpenSSL TLS 1.2 CLIENT_RANDOM was not captured"
        return 1
    }
    grep -Eq '^(CLIENT|SERVER)_(HANDSHAKE_)?TRAFFIC_SECRET' "$keylog_file" || {
        log_error "OpenSSL TLS 1.3 traffic secret was not captured"
        return 1
    }
}

case_pcapng() {
    local capture_log="$WORK_DIR/pcapng.ecapture.log"
    local pcap_file="$WORK_DIR/openssl.pcapng"
    local keylog_file="$WORK_DIR/openssl.pcapng.keys.log"
    start_capture "$capture_log" tls --libssl "$OPENSSL_LIB" --model pcapng \
        --ifname lo --pcapfile "$pcap_file" --keylogfile "$keylog_file" "tcp port $TLS_SERVER_PORT" || return 1
    if ! run_openssl_request tls13 "$WORK_DIR/pcapng.client.log"; then
        stop_capture
        return 1
    fi
    sleep 2
    stop_capture

    assert_no_capture_errors "$capture_log" || return 1
    assert_keylog "$keylog_file" || return 1
    assert_pcapng "$pcap_file" || return 1
}

main() {
    setup_linux_suite tls
    build_openssl_client

    mode_enabled text && run_case "linux/tls/text" case_text
    mode_enabled keylog && run_case "linux/tls/keylog-tls12-tls13" case_keylog
    mode_enabled pcapng && run_case "linux/tls/pcapng-with-dsb" case_pcapng

    print_summary "Linux OpenSSL TLS E2E"
}

main "$@"
