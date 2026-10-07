#!/usr/bin/env bash
# Shared, host-side assertions and result reporting for eCapture E2E tests.

if [[ -n "${ECAPTURE_E2E_TESTLIB_LOADED:-}" ]]; then
    return 0
fi
readonly ECAPTURE_E2E_TESTLIB_LOADED=1

readonly E2E_RED='\033[0;31m'
readonly E2E_GREEN='\033[0;32m'
readonly E2E_YELLOW='\033[1;33m'
readonly E2E_BLUE='\033[0;34m'
readonly E2E_NC='\033[0m'

log_info() { printf "%b[INFO]%b %s\n" "$E2E_BLUE" "$E2E_NC" "$*"; }
log_success() { printf "%b[PASS]%b %s\n" "$E2E_GREEN" "$E2E_NC" "$*"; }
log_warn() { printf "%b[WARN]%b %s\n" "$E2E_YELLOW" "$E2E_NC" "$*"; }
log_error() { printf "%b[FAIL]%b %s\n" "$E2E_RED" "$E2E_NC" "$*" >&2; }

E2E_TOTAL=0
E2E_PASSED=0
E2E_FAILED=0
E2E_FAILED_CASES=()
E2E_PACKET_CAPTURE_PID=""

run_case() {
    local name="$1"
    shift

    E2E_TOTAL=$((E2E_TOTAL + 1))
    log_info "CASE $name"
    if "$@"; then
        E2E_PASSED=$((E2E_PASSED + 1))
        log_success "$name"
        return 0
    fi

    E2E_FAILED=$((E2E_FAILED + 1))
    E2E_FAILED_CASES+=("$name")
    log_error "$name"
    return 0
}

print_summary() {
    local suite="$1"
    log_info "$suite: $E2E_PASSED/$E2E_TOTAL cases passed"
    if ((E2E_FAILED > 0)); then
        log_error "Failed cases: ${E2E_FAILED_CASES[*]}"
        return 1
    fi
    return 0
}

require_command() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        log_error "Required command not found: $command_name"
        return 1
    fi
}

assert_file_nonempty() {
    local file="$1"
    local description="${2:-file}"
    if [[ ! -s "$file" ]]; then
        log_error "$description is missing or empty: $file"
        return 1
    fi
}

assert_file_contains() {
    local file="$1"
    local literal="$2"
    local description="${3:-expected text}"
    assert_file_nonempty "$file" "$description" || return 1
    if ! grep -Fq -- "$literal" "$file"; then
        log_error "$description not found in $file: $literal"
        tail -n 80 "$file" >&2 || true
        return 1
    fi
}

assert_file_not_contains() {
    local file="$1"
    local literal="$2"
    local description="${3:-unexpected text}"
    assert_file_nonempty "$file" "$description" || return 1
    if grep -Fq -- "$literal" "$file"; then
        log_error "$description found in $file: $literal"
        grep -Fn -- "$literal" "$file" | tail -n 40 >&2 || true
        return 1
    fi
}

print_plaintext_preview() {
    local file="$1"
    local token="$2"
    local label="$3"
    local prefix="${4:-}"
    local line preview

    # The fixture puts the token in both a response header and the body.  The
    # final occurrence carries the more useful request/protocol context.
    line="$(grep -aF -- "$token" "$file" | tail -n 1)" || {
        log_error "Captured plaintext token not found for $label: $token"
        return 1
    }
    preview="$token${line#*"$token"}"
    preview="$(printf '%s' "$preview" | tr '\r\n\t' '   ' | cut -c1-50)"
    if [ -n "$prefix" ]; then
        preview="$prefix $preview"
    fi
    printf "%b[PLAINTEXT]%b %s: %s\n" "$E2E_GREEN" "$E2E_NC" "$label" "$preview"
}

start_packet_capture() {
    local interface="$1"
    local capture_filter="$2"
    local capture_file="$3"
    local capture_log="$4"

    : >"$capture_log"
    # Open the artifact from the invoking shell.  tshark drops privileges when
    # started as root and cannot itself traverse root-owned mktemp directories.
    tshark -n -i "$interface" -f "$capture_filter" -w - >"$capture_file" 2>"$capture_log" &
    E2E_PACKET_CAPTURE_PID=$!

    local attempt
    for attempt in $(seq 1 30); do
        if ! kill -0 "$E2E_PACKET_CAPTURE_PID" 2>/dev/null; then
            wait "$E2E_PACKET_CAPTURE_PID" 2>/dev/null || true
            log_error "Packet capture exited during initialization"
            cat "$capture_log" >&2 || true
            E2E_PACKET_CAPTURE_PID=""
            return 1
        fi
        if [[ -s "$capture_file" ]]; then
            return 0
        fi
        sleep 0.1
    done

    log_error "Timed out waiting for packet capture"
    stop_packet_capture
    cat "$capture_log" >&2 || true
    return 1
}

stop_packet_capture() {
    if [[ -z "$E2E_PACKET_CAPTURE_PID" ]]; then
        return 0
    fi

    if kill -0 "$E2E_PACKET_CAPTURE_PID" 2>/dev/null; then
        kill -INT "$E2E_PACKET_CAPTURE_PID" 2>/dev/null || true
        local attempt
        for attempt in $(seq 1 30); do
            if ! kill -0 "$E2E_PACKET_CAPTURE_PID" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
    fi
    if kill -0 "$E2E_PACKET_CAPTURE_PID" 2>/dev/null; then
        kill -TERM "$E2E_PACKET_CAPTURE_PID" 2>/dev/null || true
    fi
    wait "$E2E_PACKET_CAPTURE_PID" 2>/dev/null || true
    E2E_PACKET_CAPTURE_PID=""
}

assert_tls_plaintext_preview() {
    local pcap_file="$1"
    local keylog_file="$2"
    local token="$3"
    local label="$4"
    local tls_stream="${5:-0}"
    local plaintext_file="${pcap_file}.stream-${tls_stream}.plaintext.txt"
    local tshark_log="${pcap_file}.stream-${tls_stream}.tshark.log"

    assert_file_nonempty "$pcap_file" "packet capture for $label" || return 1
    assert_file_nonempty "$keylog_file" "NSS keylog for $label" || return 1
    if ! tshark -n -r "$pcap_file" -o "tls.keylog_file:$keylog_file" \
        -q -z "follow,tls,ascii,$tls_stream" >"$plaintext_file" 2>"$tshark_log"; then
        log_error "tshark could not decrypt $label (TLS stream $tls_stream)"
        cat "$tshark_log" >&2 || true
        return 1
    fi
    assert_file_contains "$plaintext_file" "$token" \
        "decrypted TLS plaintext for $label (TLS stream $tls_stream)" || return 1
    print_plaintext_preview "$plaintext_file" "$token" "$label"
}

assert_pcapng_plaintext_preview() {
    local pcap_file="$1"
    local token="$2"
    local label="$3"
    local tls_stream="${4:-0}"
    local plaintext_file="${pcap_file}.stream-${tls_stream}.plaintext.txt"
    local tshark_log="${pcap_file}.stream-${tls_stream}.tshark.log"
    local client_random_file="${pcap_file}.stream-${tls_stream}.client-randoms.txt"
    local client_random_log="${pcap_file}.stream-${tls_stream}.client-randoms.tshark.log"
    local client_random

    assert_file_nonempty "$pcap_file" "pcapng capture for $label" || return 1
    # Clear any keylog configured in the host's Wireshark profile. Successful
    # decryption must come from the TLS Decryption Secrets Block embedded in
    # eCapture's pcapng output.
    if ! tshark -n -r "$pcap_file" -o tls.keylog_file: -q -z "follow,tls,ascii,$tls_stream" \
        >"$plaintext_file" 2>"$tshark_log"; then
        log_error "tshark could not decrypt embedded pcapng secrets for $label (TLS stream $tls_stream)"
        cat "$tshark_log" >&2 || true
        return 1
    fi
    assert_file_contains "$plaintext_file" "$token" \
        "DSB-decrypted TLS plaintext for $label (TLS stream $tls_stream)" || return 1

    if ! tshark -n -r "$pcap_file" \
        -Y "tcp.stream == $tls_stream && tls.handshake.type == 1" \
        -T fields -e tls.handshake.random >"$client_random_file" 2>"$client_random_log"; then
        log_error "tshark could not extract CLIENT_RANDOM for $label"
        cat "$client_random_log" >&2 || true
        return 1
    fi
    client_random="$(awk 'NF { value=$1; gsub(/[:,]/, "", value); print value; exit }' "$client_random_file")"
    if [[ ! "$client_random" =~ ^[0-9A-Fa-f]{64}$ ]]; then
        log_error "Invalid or missing CLIENT_RANDOM for $label"
        return 1
    fi

    print_plaintext_preview "$plaintext_file" "$token" "$label" \
        "CLIENT_RANDOM=$client_random"
}

assert_no_capture_errors() {
    local log_file="$1"
    assert_file_nonempty "$log_file" "eCapture log" || return 1

    local error_pattern='(^|[[:space:]])FTL([[:space:]]|$)|panic:|Failed to decode event|lost [1-9][0-9]* samples|Perf buffer full, samples lost|lost_samples"?[=:][[:space:]]*[1-9][0-9]*|pcap write packet channel full|keylog write channel full|failed to write packet to pcapng|save pcapng err|failed to write (queued DSB to pcapng|DSB on shutdown)|failed to flush (after DSB write|on shutdown)|failed to (load|attach|start)'
    if grep -Eiq "$error_pattern" "$log_file"; then
        log_error "eCapture reported a fatal, decode, loss, pcap write, load, attach, or start error"
        grep -Ein "$error_pattern" "$log_file" | tail -n 40 >&2 || true
        return 1
    fi
}

assert_keylog() {
    local keylog_file="$1"
    assert_file_nonempty "$keylog_file" "NSS keylog" || return 1

    local keylog_pattern='^(CLIENT_RANDOM|CLIENT_EARLY_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_[0-9]+|SERVER_TRAFFIC_SECRET_[0-9]+|EXPORTER_SECRET) [0-9A-Fa-f]{64} [0-9A-Fa-f]{32,}$'
    if ! grep -Eq "$keylog_pattern" "$keylog_file"; then
        log_error "No valid NSS keylog line found in $keylog_file"
        head -n 20 "$keylog_file" >&2 || true
        return 1
    fi

    if grep -Evq "^#|^[[:space:]]*$|$keylog_pattern" "$keylog_file"; then
        log_error "Malformed line found in NSS keylog: $keylog_file"
        grep -Env "^#|^[[:space:]]*$|$keylog_pattern" "$keylog_file" | head -n 20 >&2 || true
        return 1
    fi
}

mode_enabled() {
    local requested="$1"
    local mode
    for mode in ${E2E_MODES:-text keylog pcapng}; do
        if [[ "$mode" == "$requested" ]]; then
            return 0
        fi
    done
    return 1
}

validate_modes() {
    local mode
    for mode in ${E2E_MODES:-text keylog pcapng}; do
        case "$mode" in
            text|keylog|pcapng) ;;
            *)
                log_error "Unsupported E2E mode '$mode'; expected text, keylog, or pcapng"
                return 1
                ;;
        esac
    done
}
