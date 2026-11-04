#!/usr/bin/env bash
# Strict CLI rejection and graceful-shutdown checks on a supported Linux host.

set -euo pipefail

E2E_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/linux/common_config_test.sh
source "$E2E_SCRIPT_DIR/linux/common_config_test.sh"
trap 'status=$?; common_config_cleanup "$status"; exit $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

OPENSSL_LIB=""

expect_rejected() {
    local name="$1" expected="$2" status=0
    shift 2
    local output="$WORK_DIR/$name.log"
    timeout --signal=TERM --kill-after=2s 15s "$ECAPTURE_BINARY" "$@" >"$output" 2>&1 || status=$?
    if ((status == 0 || status >= 124)); then
        log_error "$name must reject promptly, not succeed, time out, or crash (exit=$status)"
        return 1
    fi
    assert_file_contains "$output" "$expected" "$name rejection reason"
}

case_shutdown() {
    local signal="$1"
    prepare_common_case "signal-${signal,,}" || return 1
    start_common_capture tls tls --libssl "$OPENSSL_LIB" -m text || return 1
    stop_common_capture "$signal" || return 1
    assert_no_capture_errors "$CAPTURE_LOG" || return 1
    assert_no_capture_errors "$OPERATIONAL_LOG" || return 1
    assert_file_contains "$OPERATIONAL_LOG" "Probe closed" "SIG$signal probe cleanup" || return 1
    assert_file_contains "$OPERATIONAL_LOG" "bye bye" "SIG$signal CLI shutdown"
}

main() {
    setup_common_config_suite || return 1
    require_command cc || return 1
    require_command ldd || return 1
    local client="$WORK_DIR/openssl_client"
    cc -O2 -Wall -Wextra -Werror -o "$client" "$E2E_DIR/fixtures/c/openssl_client.c" -lssl -lcrypto || return 1
    OPENSSL_LIB="$(ldd "$client" | awk '/libssl[.]so/ && $2 == "=>" {print $3; exit}')"
    [[ -f "$OPENSSL_LIB" ]] || { log_error "Cannot resolve the OpenSSL fixture library"; return 1; }

    run_case "cli/missing-openssl" expect_rejected missing-openssl 'openssl path not found' \
        tls --libssl "$WORK_DIR/no-libssl.so"
    run_case "cli/missing-gotls-elf" expect_rejected missing-gotls-elf 'failed to parse Go ELF file' \
        gotls --elfpath "$WORK_DIR/no-go-binary"
    run_case "cli/invalid-btf" expect_rejected invalid-btf 'invalid btf_mode: 3' \
        tls --libssl "$OPENSSL_LIB" --btf 3
    run_case "cli/nonpositive-mapsize" expect_rejected nonpositive-mapsize 'per_cpu_map_size must be positive' \
        tls --libssl "$OPENSSL_LIB" --mapsize 0
    run_case "cli/negative-pid" expect_rejected negative-pid 'invalid argument' \
        tls --libssl "$OPENSSL_LIB" --pid=-1
    run_case "cli/missing-interface" expect_rejected missing-interface "network interface 'ecap-no-iface' not found" \
        tls --libssl "$OPENSSL_LIB" -m pcapng --ifname ecap-no-iface --eventaddr "$WORK_DIR/no-iface.pcapng"
    run_case "cli/empty-pcapng-destination" expect_rejected empty-pcapng 'pcapng output requires an explicit destination' \
        tls --libssl "$OPENSSL_LIB" -m pcapng --ifname lo --pcapfile= --keylogfile=
    run_case "cli/unwritable-event-file" expect_rejected unwritable-file 'failed to open file' \
        tls --libssl "$OPENSSL_LIB" --eventaddr "/proc/ecapture-e2e-$BASHPID"
    run_case "cli/invalid-pcap-filter" expect_rejected invalid-filter 'failed to inject pcap filter' \
        tls --libssl "$OPENSSL_LIB" -m pcapng --ifname lo --eventaddr "$WORK_DIR/invalid-filter.pcapng" \
        'this is not a valid capture filter!!!'
    run_case "runtime/sigint" case_shutdown INT
    run_case "runtime/sigterm" case_shutdown TERM
    print_summary "Linux CLI edge cases"
}

main "$@"
