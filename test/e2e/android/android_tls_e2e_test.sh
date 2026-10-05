#!/usr/bin/env bash
# Android 13+ Conscrypt/BoringSSL TLS probe E2E tests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/android/common_android.sh
source "$SCRIPT_DIR/common_android.sh"

LOCAL_ECAPTURE="${ECAPTURE_BINARY:-$ROOT_DIR/bin/ecapture}"
LOCAL_CLIENT="${ANDROID_BORINGSSL_CLIENT:-$SCRIPT_DIR/android_boringssl_client.jar}"
DEVICE_ECAPTURE=""
DEVICE_CLIENT=""
BORINGSSL_LIB=""
BORINGSSL_VERSION=""
ANDROID_CLIENT_GATE=""
ANDROID_CLIENT_DEVICE_LOG=""

deploy_android_workloads() {
    [[ -f "$LOCAL_ECAPTURE" ]] || {
        log_error "Android eCapture binary not found: $LOCAL_ECAPTURE"
        return 1
    }
    [[ -f "$LOCAL_CLIENT" ]] || {
        log_error "Android BoringSSL client not found: $LOCAL_CLIENT"
        log_error "Build it with test/e2e/android/build_boringssl_client.sh"
        return 1
    }

    DEVICE_ECAPTURE="$ANDROID_DEVICE_DIR/ecapture"
    DEVICE_CLIENT="$ANDROID_DEVICE_DIR/android_boringssl_client.jar"
    adb_push "$LOCAL_ECAPTURE" "$DEVICE_ECAPTURE"
    adb_push "$LOCAL_CLIENT" "$DEVICE_CLIENT"
    adb_cmd shell "chmod 755 '$DEVICE_ECAPTURE'"
    if ! adb_cmd shell "'$DEVICE_ECAPTURE' --version" >"$ANDROID_WORK_DIR/ecapture.version.log" 2>&1; then
        log_error "Android eCapture binary cannot execute on the connected device"
        cat "$ANDROID_WORK_DIR/ecapture.version.log" >&2 || true
        return 1
    fi

    BORINGSSL_LIB="$(find_android_boringssl)"
    local release
    release="$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
    BORINGSSL_VERSION="boringssl_a_${release%%.*}"
    log_info "BoringSSL library: $BORINGSSL_LIB ($BORINGSSL_VERSION)"
}

run_android_https_request() {
    local tls_version="$1"
    local output_file="$2"
    local version_flag
    case "$tls_version" in
        tls12) version_flag="1.2" ;;
        tls13) version_flag="1.3" ;;
        *) log_error "Unknown Android TLS fixture version: $tls_version"; return 1 ;;
    esac
    adb_cmd_timeout 20 shell \
        "CLASSPATH='$DEVICE_CLIENT' app_process /system/bin AndroidHttpsClient '$ANDROID_TLS_URL' '$ANDROID_E2E_TOKEN' '$version_flag'" \
        >"$output_file" 2>&1
    assert_file_contains "$output_file" "$ANDROID_E2E_TOKEN" "Android Conscrypt response"
}

# Start app_process behind a file gate so its PID can be supplied to eCapture
# before the TLS request begins. Text mode otherwise observes every platform
# BoringSSL user and can overflow the perf buffer on busy emulator images.
prepare_android_https_request() {
    local tls_version="$1"
    local version_flag
    case "$tls_version" in
        tls12) version_flag="1.2" ;;
        tls13) version_flag="1.3" ;;
        *) log_error "Unknown Android TLS fixture version: $tls_version"; return 1 ;;
    esac

    ANDROID_CLIENT_GATE="$ANDROID_DEVICE_DIR/client.start"
    ANDROID_CLIENT_DEVICE_LOG="$ANDROID_DEVICE_DIR/client.output"
    adb_cmd shell "rm -f '$ANDROID_CLIENT_GATE' '$ANDROID_CLIENT_DEVICE_LOG'"

    local client_command output
    client_command="while [ ! -f '$ANDROID_CLIENT_GATE' ]; do sleep 0.1; done; export CLASSPATH='$DEVICE_CLIENT'; exec app_process /system/bin AndroidHttpsClient '$ANDROID_TLS_URL' '$ANDROID_E2E_TOKEN' '$version_flag'"
    output="$(adb_cmd shell "nohup sh -c \"$client_command\" >'$ANDROID_CLIENT_DEVICE_LOG' 2>&1 </dev/null & echo \$!")"
    ANDROID_CLIENT_PID="$(printf '%s\n' "$output" | tr -d '\r' | grep -E '^[0-9]+$' | tail -n 1)"
    if [[ -z "$ANDROID_CLIENT_PID" ]]; then
        log_error "Could not determine gated Android client PID"
        return 1
    fi
    if ! adb_cmd shell "kill -0 '$ANDROID_CLIENT_PID'" >/dev/null 2>&1; then
        log_error "Gated Android client exited before capture started"
        ANDROID_CLIENT_PID=""
        return 1
    fi
}

run_prepared_android_https_request() {
    local output_file="$1"
    adb_cmd shell "touch '$ANDROID_CLIENT_GATE'"

    local attempt request_complete=0
    for attempt in $(seq 1 200); do
        if adb_cmd shell "grep -Fq '$ANDROID_E2E_TOKEN method=GET protocol=HTTP/1.1 path=/e2e' '$ANDROID_CLIENT_DEVICE_LOG'" \
            >/dev/null 2>&1; then
            request_complete=1
            break
        fi
        if ! adb_cmd shell "kill -0 '$ANDROID_CLIENT_PID'" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    if [[ "$request_complete" -ne 1 ]]; then
        log_error "Gated Android Conscrypt client did not produce the expected response"
        stop_android_client
        return 1
    fi

    if ! adb_pull "$ANDROID_CLIENT_DEVICE_LOG" "$output_file"; then
        stop_android_client
        return 1
    fi
    # Some Android releases keep app_process alive after the request because
    # platform runtime threads remain active. The response marker, rather than
    # process exit, defines completion for this workload.
    stop_android_client
    assert_file_contains "$output_file" "$ANDROID_E2E_TOKEN" "Android Conscrypt response"
}

pull_capture_log() {
    local device_log="$1"
    local local_log="$2"
    adb_pull "$device_log" "$local_log"
    assert_no_capture_errors "$local_log"
}

case_text() {
    local device_log="$ANDROID_DEVICE_DIR/text.ecapture.log"
    local local_log="$ANDROID_WORK_DIR/text.ecapture.log"
    prepare_android_https_request tls13 || return 1
    if ! start_android_capture "$device_log" "$DEVICE_ECAPTURE" tls \
        --libssl "$BORINGSSL_LIB" --ssl_version "$BORINGSSL_VERSION" \
        --model text --pid "$ANDROID_CLIENT_PID"; then
        stop_android_client
        return 1
    fi
    if ! run_prepared_android_https_request "$ANDROID_WORK_DIR/text.client.log"; then
        stop_android_capture
        return 1
    fi
    sleep 1
    stop_android_capture

    pull_capture_log "$device_log" "$local_log" || return 1
    assert_file_contains "$local_log" "$ANDROID_E2E_TOKEN" "captured Android BoringSSL plaintext" || return 1
    print_plaintext_preview "$local_log" "$ANDROID_E2E_TOKEN" "android/boringssl/text"
}

case_keylog() {
    local device_log="$ANDROID_DEVICE_DIR/keylog.ecapture.log"
    local device_keylog="$ANDROID_DEVICE_DIR/boringssl.keys.log"
    local local_log="$ANDROID_WORK_DIR/keylog.ecapture.log"
    local local_keylog="$ANDROID_WORK_DIR/boringssl.keys.log"
    local packet_file="$ANDROID_WORK_DIR/boringssl.keylog.pcapng"
    local packet_log="$ANDROID_WORK_DIR/boringssl.keylog.tshark-capture.log"
    start_packet_capture lo "tcp port $ANDROID_TLS_PORT" "$packet_file" "$packet_log" || return 1
    if ! start_android_capture "$device_log" "$DEVICE_ECAPTURE" tls \
        --libssl "$BORINGSSL_LIB" --ssl_version "$BORINGSSL_VERSION" \
        --model keylog --keylogfile "$device_keylog"; then
        stop_packet_capture
        return 1
    fi
    if ! run_android_https_request tls12 "$ANDROID_WORK_DIR/keylog.tls12.client.log" || \
       ! run_android_https_request tls13 "$ANDROID_WORK_DIR/keylog.tls13.client.log"; then
        stop_android_capture
        stop_packet_capture
        return 1
    fi
    sleep 1
    stop_android_capture
    stop_packet_capture

    pull_capture_log "$device_log" "$local_log" || return 1
    adb_pull "$device_keylog" "$local_keylog" || return 1
    assert_keylog "$local_keylog" || return 1
    grep -Eq '^CLIENT_RANDOM ' "$local_keylog" || {
        log_error "Android BoringSSL TLS 1.2 CLIENT_RANDOM was not captured"
        return 1
    }
    grep -Eq '^(CLIENT|SERVER)_(HANDSHAKE_)?TRAFFIC_SECRET' "$local_keylog" || {
        log_error "Android BoringSSL TLS 1.3 traffic secret was not captured"
        return 1
    }
    assert_tls_plaintext_preview \
        "$packet_file" "$local_keylog" "$ANDROID_E2E_TOKEN" "android/boringssl/keylog"
}

case_pcapng() {
    local device_log="$ANDROID_DEVICE_DIR/pcapng.ecapture.log"
    local device_pcap="$ANDROID_DEVICE_DIR/boringssl.pcapng"
    local local_log="$ANDROID_WORK_DIR/pcapng.ecapture.log"
    local local_pcap="$ANDROID_WORK_DIR/boringssl.pcapng"
    start_android_capture "$device_log" "$DEVICE_ECAPTURE" tls \
        --libssl "$BORINGSSL_LIB" --ssl_version "$BORINGSSL_VERSION" \
        --model pcapng --ifname lo --pcapfile "$device_pcap" --keylogfile= \
        "tcp port $ANDROID_TLS_PORT" || return 1
    if ! run_android_https_request tls12 "$ANDROID_WORK_DIR/pcapng.tls12.client.log" || \
       ! run_android_https_request tls13 "$ANDROID_WORK_DIR/pcapng.tls13.client.log"; then
        stop_android_capture
        return 1
    fi
    sleep 2
    stop_android_capture

    pull_capture_log "$device_log" "$local_log" || return 1
    adb_pull "$device_pcap" "$local_pcap" || return 1
    assert_android_pcapng "$local_pcap" || return 1
    assert_pcapng_plaintext_preview \
        "$local_pcap" "$ANDROID_E2E_TOKEN" "android/boringssl/pcapng"
}

main() {
    setup_android_suite
    deploy_android_workloads

    mode_enabled text && run_case "android/boringssl/text" case_text
    mode_enabled keylog && run_case "android/boringssl/keylog" case_keylog
    mode_enabled pcapng && run_case "android/boringssl/pcapng-with-dsb" case_pcapng

    print_summary "Android BoringSSL TLS E2E"
}

main "$@"
