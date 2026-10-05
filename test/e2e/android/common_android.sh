#!/usr/bin/env bash
# Android 13+ E2E harness for rooted devices/emulators.

set -euo pipefail

ANDROID_E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$ANDROID_E2E_DIR/.." && pwd)"
ROOT_DIR="$(cd "$E2E_DIR/../.." && pwd)"

# shellcheck source=test/e2e/lib/testlib.sh
source "$E2E_DIR/lib/testlib.sh"

ANDROID_CAPTURE_PID=""
ANDROID_HOST_SERVER_PID=""
ANDROID_WORK_DIR=""
ANDROID_DEVICE_DIR=""
ANDROID_TLS_PORT=""
ANDROID_TLS_URL=""
ANDROID_E2E_TOKEN=""
ANDROID_PCAPNG_CHECK=""

adb_cmd() {
    if [[ -n "${ADB_SERIAL:-}" ]]; then
        command adb -s "$ADB_SERIAL" "$@"
    else
        command adb "$@"
    fi
}

adb_cmd_timeout() {
    local duration="$1"
    shift
    if [[ -n "${ADB_SERIAL:-}" ]]; then
        timeout "$duration" adb -s "$ADB_SERIAL" "$@"
    else
        timeout "$duration" adb "$@"
    fi
}

check_android_host() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        log_error "Android E2E execution must be hosted on Linux"
        return 1
    fi
    local major minor
    IFS=. read -r major minor _ <<<"$(uname -r)"
    if ((major < 4 || (major == 4 && minor < 18))); then
        log_error "Android E2E host kernel $(uname -r) is too old; require 4.18+"
        return 1
    fi
}

check_adb() {
    require_command adb || return 1
    local devices
    devices="$(adb_cmd devices | awk 'NR > 1 && $2 == "device" {count++} END {print count+0}')"
    if [[ "$devices" -ne 1 && -z "${ADB_SERIAL:-}" ]]; then
        log_error "Expected exactly one Android device, found $devices; set ADB_SERIAL when multiple devices are attached"
        adb_cmd devices >&2
        return 1
    fi
}

check_android_device() {
    adb_cmd get-state >/dev/null 2>&1 || {
        log_error "Android device is not ready"
        return 1
    }
}

check_android_version() {
    local sdk release
    sdk="$(adb_cmd shell getprop ro.build.version.sdk | tr -d '\r')"
    release="$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
    if [[ ! "$sdk" =~ ^[0-9]+$ ]] || ((sdk < 33)); then
        log_error "Android 13/API 33 or newer is required (found release=$release api=$sdk)"
        return 1
    fi
    log_info "Android release=$release api=$sdk"
}

check_android_arch() {
    local arch
    arch="$(adb_cmd shell uname -m | tr -d '\r')"
    case "$arch" in
        x86_64|aarch64|arm64) log_info "Android architecture: $arch" ;;
        *) log_error "Unsupported Android architecture: $arch"; return 1 ;;
    esac
}

check_android_kernel() {
    local arch kernel major minor required_major required_minor
    arch="$(adb_cmd shell uname -m | tr -d '\r')"
    kernel="$(adb_cmd shell uname -r | tr -d '\r')"
    IFS=. read -r major minor _ <<<"$kernel"
    case "$arch" in
        x86_64) required_major=4; required_minor=18 ;;
        aarch64|arm64) required_major=5; required_minor=5 ;;
        *) return 1 ;;
    esac
    if ((major < required_major || (major == required_major && minor < required_minor))); then
        log_error "Android kernel $kernel is too old for $arch"
        return 1
    fi
    log_info "Android kernel: $kernel"
}

check_android_root() {
    local attempt output="" uid=""
    for attempt in {1..5}; do
        # sys.boot_completed can become true just before adbd is ready to
        # restart as root, especially on new API-level emulator images.
        output="$(adb_cmd_timeout 20s root 2>&1)" || true
        adb_cmd_timeout 30s wait-for-device >/dev/null 2>&1 || true
        uid="$(adb_cmd_timeout 10s shell id -u 2>/dev/null | tr -d '\r' || true)"
        if [[ "$uid" == "0" ]]; then
            return 0
        fi

        if ((attempt < 5)); then
            log_info "adbd root is not ready (attempt $attempt/5); retrying"
            sleep 2
        fi
    done

    log_error "adb root failed after 5 attempts (uid=${uid:-unknown}): ${output:-no adb output}"
    return 1
}

prepare_android_selinux() {
    local state
    state="$(adb_cmd shell getenforce 2>/dev/null | tr -d '\r' || true)"
    if [[ "$state" == "Enforcing" ]]; then
        adb_cmd shell setenforce 0 >/dev/null 2>&1 || true
        state="$(adb_cmd shell getenforce 2>/dev/null | tr -d '\r' || true)"
    fi
    if [[ "$state" == "Enforcing" ]]; then
        log_error "SELinux remains enforcing; the E2E image must permit eBPF attachment"
        return 1
    fi
    log_info "SELinux: ${state:-unknown}"
}

check_android_prerequisites() {
    check_android_host
    require_command timeout
    check_adb
    check_android_device
    check_android_version
    check_android_arch
    check_android_kernel
    check_android_root
    prepare_android_selinux
}

adb_push() {
    local source_file="$1"
    local destination="$2"
    [[ -f "$source_file" ]] || {
        log_error "File not found: $source_file"
        return 1
    }
    adb_cmd push "$source_file" "$destination" >/dev/null
}

adb_pull() {
    local source_file="$1"
    local destination="$2"
    adb_cmd pull "$source_file" "$destination" >/dev/null
}

adb_file_exists() {
    adb_cmd shell "test -f '$1'" >/dev/null 2>&1
}

find_android_boringssl() {
    local candidate
    for candidate in \
        /apex/com.android.conscrypt/lib64/libssl.so \
        /apex/com.android.conscrypt/lib/libssl.so \
        /system/lib64/libssl.so \
        /system/lib/libssl.so; do
        if adb_file_exists "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    log_error "Android platform BoringSSL libssl.so was not found"
    return 1
}

create_android_work_dir() {
    local artifact_root="${E2E_ARTIFACT_ROOT:-/tmp/ecapture-e2e-android}"
    mkdir -p "$artifact_root"
    ANDROID_WORK_DIR="$(mktemp -d "$artifact_root/boringssl.XXXXXX")"
    ANDROID_DEVICE_DIR="/data/local/tmp/ecapture-e2e-$$"
    ANDROID_E2E_TOKEN="ECAPTURE_E2E_ANDROID_$$_${RANDOM}"
    adb_cmd shell "mkdir -p '$ANDROID_DEVICE_DIR'"
    log_info "Android artifacts: $ANDROID_WORK_DIR"
}

build_android_host_helpers() {
    mkdir -p "$ANDROID_WORK_DIR/helpers"
    go build -o "$ANDROID_WORK_DIR/helpers/tls_server" "$E2E_DIR/fixtures/tls_server/main.go"
    go build -o "$ANDROID_WORK_DIR/helpers/pcapng_check" "$E2E_DIR/fixtures/pcapng_check/main.go"
    ANDROID_PCAPNG_CHECK="$ANDROID_WORK_DIR/helpers/pcapng_check"
}

start_android_tls_fixture() {
    local ready_file="$ANDROID_WORK_DIR/tls-server.addr"
    "$ANDROID_WORK_DIR/helpers/tls_server" --listen 127.0.0.1:0 \
        --ready-file "$ready_file" --token "$ANDROID_E2E_TOKEN" \
        >"$ANDROID_WORK_DIR/tls-server.log" 2>&1 &
    ANDROID_HOST_SERVER_PID=$!

    local attempt address
    for attempt in $(seq 1 50); do
        if [[ -s "$ready_file" ]]; then
            address="$(tr -d '\r\n' <"$ready_file")"
            ANDROID_TLS_PORT="${address##*:}"
            adb_cmd reverse "tcp:$ANDROID_TLS_PORT" "tcp:$ANDROID_TLS_PORT"
            ANDROID_TLS_URL="https://127.0.0.1:$ANDROID_TLS_PORT/e2e"
            log_info "Android TLS fixture through adb reverse: $ANDROID_TLS_URL"
            return 0
        fi
        if ! kill -0 "$ANDROID_HOST_SERVER_PID" 2>/dev/null; then
            cat "$ANDROID_WORK_DIR/tls-server.log" >&2 || true
            return 1
        fi
        sleep 0.1
    done
    log_error "Timed out waiting for host TLS fixture"
    return 1
}

start_android_capture() {
    local device_log="$1"
    shift
    local command_line="$*"
    local output
    output="$(adb_cmd shell "nohup $command_line >'$device_log' 2>&1 </dev/null & echo \$!")"
    ANDROID_CAPTURE_PID="$(printf '%s\n' "$output" | tr -d '\r' | grep -E '^[0-9]+$' | tail -n 1)"
    if [[ -z "$ANDROID_CAPTURE_PID" ]]; then
        log_error "Could not determine Android eCapture PID"
        return 1
    fi

    local attempt
    for attempt in $(seq 1 30); do
        if ! adb_cmd shell "kill -0 '$ANDROID_CAPTURE_PID'" >/dev/null 2>&1; then
            log_error "Android eCapture exited during initialization"
            adb_cmd shell "tail -n 100 '$device_log'" >&2 || true
            ANDROID_CAPTURE_PID=""
            return 1
        fi
        if adb_cmd shell "grep -Eqi 'probe started successfully' '$device_log'" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    return 0
}

stop_android_capture() {
    if [[ -z "$ANDROID_CAPTURE_PID" ]]; then
        return 0
    fi
    adb_cmd shell "kill -INT '$ANDROID_CAPTURE_PID'" >/dev/null 2>&1 || true
    local attempt
    for attempt in $(seq 1 30); do
        if ! adb_cmd shell "kill -0 '$ANDROID_CAPTURE_PID'" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    if adb_cmd shell "kill -0 '$ANDROID_CAPTURE_PID'" >/dev/null 2>&1; then
        adb_cmd shell "kill -TERM '$ANDROID_CAPTURE_PID'" >/dev/null 2>&1 || true
        sleep 0.5
    fi
    if adb_cmd shell "kill -0 '$ANDROID_CAPTURE_PID'" >/dev/null 2>&1; then
        adb_cmd shell "kill -KILL '$ANDROID_CAPTURE_PID'" >/dev/null 2>&1 || true
    fi
    ANDROID_CAPTURE_PID=""
}

assert_android_pcapng() {
    local pcap_file="$1"
    assert_file_nonempty "$pcap_file" "Android pcapng capture" || return 1
    "$ANDROID_PCAPNG_CHECK" --require-dsb "$pcap_file"
}

android_suite_cleanup() {
    stop_android_capture || true
    if [[ -n "$ANDROID_TLS_PORT" ]]; then
        adb_cmd reverse --remove "tcp:$ANDROID_TLS_PORT" >/dev/null 2>&1 || true
    fi
    if [[ -n "$ANDROID_HOST_SERVER_PID" ]] && kill -0 "$ANDROID_HOST_SERVER_PID" 2>/dev/null; then
        kill -TERM "$ANDROID_HOST_SERVER_PID" 2>/dev/null || true
        wait "$ANDROID_HOST_SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "$ANDROID_DEVICE_DIR" ]]; then
        adb_cmd shell "rm -rf '$ANDROID_DEVICE_DIR'" >/dev/null 2>&1 || true
    fi
    if [[ -n "$ANDROID_WORK_DIR" && -d "$ANDROID_WORK_DIR" ]]; then
        if [[ "${E2E_KEEP_ARTIFACTS:-0}" == "1" || "$E2E_FAILED" -gt 0 ]]; then
            log_info "Preserving Android artifacts: $ANDROID_WORK_DIR"
        else
            rm -rf -- "$ANDROID_WORK_DIR"
        fi
    fi
}

setup_android_suite() {
    check_android_prerequisites
    validate_modes
    require_command go
    create_android_work_dir
    trap android_suite_cleanup EXIT
    trap 'exit 130' INT TERM
    build_android_host_helpers
    start_android_tls_fixture
}
