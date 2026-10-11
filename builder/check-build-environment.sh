#!/usr/bin/env bash

set -euo pipefail

target_arch="${1:-}"
target_os="${2:-linux}"

version_at_least() {
    local actual="$1"
    local required="$2"
    [[ "$(printf '%s\n%s\n' "$required" "$actual" | sort -V | head -n 1)" == "$required" ]]
}

if [[ -z "$target_arch" ]]; then
    echo "usage: $0 <amd64|arm64|loong64> [linux|android]" >&2
    exit 2
fi
case "$target_os" in
    linux|android) ;;
    *)
        echo "unsupported target OS: $target_os" >&2
        exit 1
        ;;
esac
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "eCapture compilation requires Linux; found $(uname -s)" >&2
    exit 1
fi

host_arch="$(uname -m)"
case "$host_arch" in
    x86_64) host_goarch=amd64; minimum_kernel=4.18 ;;
    aarch64|arm64) host_goarch=arm64; minimum_kernel=5.5 ;;
    loongarch64|loong64) host_goarch=loong64; minimum_kernel=6.6 ;;
    *)
        echo "unsupported build host architecture: $host_arch" >&2
        exit 1
        ;;
esac

case "$target_arch" in
    amd64|arm64) ;;
    loong64)
        if [[ "$target_os" != "linux" ]]; then
            echo "Loong64 is supported only for Linux" >&2
            exit 1
        fi
        if [[ "$host_arch" != "x86_64" ]]; then
            echo "Loong64 release builds require an x86_64 cross-build host; found $host_arch" >&2
            exit 1
        fi
        if [[ ! -r /etc/os-release ]]; then
            echo "cannot identify Loong64 cross-build distribution: /etc/os-release is missing" >&2
            exit 1
        fi
        # shellcheck disable=SC1091
        source /etc/os-release
        if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
            echo "Loong64 cross-builds require Ubuntu 24.04 x86_64; found ${PRETTY_NAME:-unknown}" >&2
            exit 1
        fi
        ;;
    *)
        echo "unsupported target architecture: $target_arch" >&2
        exit 1
        ;;
esac

host_kernel="$(uname -r | cut -d- -f1)"
if ! version_at_least "$host_kernel" "$minimum_kernel"; then
    echo "host kernel $host_kernel is too old for $host_goarch; require $minimum_kernel or newer" >&2
    exit 1
fi

if [[ "$target_arch" == "loong64" ]]; then
    required_major=18
    tools=(
        clang-18 clang++-18 llc-18 ld.lld-18 llvm-ar-18 llvm-ranlib-18
        llvm-nm-18 llvm-strip-18 llvm-objcopy-18 llvm-objdump-18 llvm-readelf-18
    )

    tool_major() {
        "$1" --version 2>&1 |
            sed -nE '/([Vv]ersion|LLD)[[:space:]]+[0-9]+/ { s/.*([Vv]ersion|LLD)[[:space:]]+([0-9]+).*/\2/; p; q; }'
    }

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "missing required Loong64 LLVM tool: $tool" >&2
            exit 1
        fi
        major="$(tool_major "$tool")"
        if [[ "$major" != "$required_major" ]]; then
            echo "$tool must be LLVM major $required_major; found ${major:-unknown}" >&2
            exit 1
        fi
    done

    sysroot="${LOONG64_SYSROOT:-/}"
    target_root="${LOONG64_TARGET_ROOT:-/usr/loongarch64-linux-gnu}"
    runtime_dir="${LOONG64_GCC_RUNTIME_DIR:-/usr/lib/gcc-cross/loongarch64-linux-gnu/13}"

    if [[ ! -d "$sysroot" ]]; then
        echo "Loong64 sysroot is unavailable: $sysroot" >&2
        exit 1
    fi

    required_target_files=(
        include/stdio.h
        lib/crt1.o
        lib/Scrt1.o
        lib/rcrt1.o
        lib/crti.o
        lib/crtn.o
        lib/libc.a
    )
    for relative_path in "${required_target_files[@]}"; do
        if [[ ! -f "$target_root/$relative_path" ]]; then
            echo "incomplete Loong64 target root: missing $target_root/$relative_path" >&2
            exit 1
        fi
    done
    for runtime_file in \
        crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o \
        libgcc.a libatomic.a; do
        if [[ ! -f "$runtime_dir/$runtime_file" ]]; then
            echo "missing Loong64 target runtime: $runtime_dir/$runtime_file" >&2
            exit 1
        fi
    done

    machine="$("$(dirname "$0")/loong64-clang" -dumpmachine)"
    if [[ "$machine" != "loongarch64-unknown-linux-gnu" && "$machine" != "loongarch64-linux-gnu" ]]; then
        echo "Loong64 Clang wrapper selected unexpected target: $machine" >&2
        exit 1
    fi
fi
