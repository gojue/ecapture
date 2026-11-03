#!/usr/bin/env bash
# Validate the preflight matrix without loading eBPF or requiring root.
set -euo pipefail
[[ "$(uname -s)" == Linux ]] || { echo 'Platform tests require Linux' >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_error() { printf '%s\n' "$*" >&2; }
# shellcheck source=test/e2e/linux/platform.sh
source "$SCRIPT_DIR/platform.sh"
checks=0
expect_allowed() {
    check_linux_platform "$@" || { echo "Unexpected rejection: $*" >&2; exit 1; }
    checks=$((checks + 1))
}
expect_rejected() {
    if check_linux_platform "$@" >/dev/null 2>&1; then
        echo "Unexpected acceptance: $*" >&2
        exit 1
    fi
    checks=$((checks + 1))
}
for distro in ubuntu debian; do
    release=22.04
    [[ "$distro" != debian ]] || release=13
    expect_allowed Linux "$distro" "$release" x86_64 4.18.0 0
    expect_allowed Linux "$distro" "$release" aarch64 5.5.0 0
    expect_allowed Linux "$distro" "$release" arm64 7.0.0-42-generic 0
    expect_allowed Linux "$distro" "$release" loongarch64 6.6.0 0
    expect_allowed Linux "$distro" "$release" loong64 7.0.14-26-pve 0
    expect_rejected Linux "$distro" "$release" x86_64 4.17.99 0
    expect_rejected Linux "$distro" "$release" aarch64 5.4.99 0
    expect_rejected Linux "$distro" "$release" loongarch64 6.5.99 0
    expect_rejected Linux "$distro" "$release" riscv64 7.0.0 0
    expect_rejected Linux "$distro" "$release" loongarch64 7.0.0 1000
    expect_rejected Linux "$distro" "$release" loongarch64 unknown 0
done
expect_rejected Darwin debian 13 loongarch64 7.0.0 0
expect_rejected Linux fedora 43 loongarch64 7.0.0 0
expect_rejected Linux debian 12 loongarch64 7.0.0 0
expect_rejected Linux ubuntu 20.04 x86_64 7.0.0 0
expect_rejected Linux debian '' loongarch64 7.0.0 0
expect_rejected Linux debian testing loongarch64 7.0.0 0
expect_allowed Linux ubuntu 26.04 x86_64 7.0.0 0
expect_allowed Linux debian 13.6 loongarch64 7.0.14-26-pve 0
printf 'PASS: %d Linux E2E platform checks\n' "$checks"
