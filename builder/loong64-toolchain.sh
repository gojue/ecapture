#!/usr/bin/env bash
# Shared defaults for the native Debian and Ubuntu cross-build wrappers.
# Source this file; the caller performs platform and tool-version validation.
# Variables are consumed by the sourcing preflight/compiler wrapper.
# shellcheck disable=SC2034
llvm_major=22
llvm_version=22.1.8
linker=lld
sysroot="${LOONG64_SYSROOT:-/}"
case "$(uname -m)" in
    loongarch64|loong64)
        target_root="${LOONG64_TARGET_ROOT:-/usr}"
        target_libdir="${LOONG64_TARGET_LIBDIR:-$target_root/lib/loongarch64-linux-gnu}"
        if [[ -n "${LOONG64_GCC_RUNTIME_DIR:-}" ]]; then
            runtime_dir="$LOONG64_GCC_RUNTIME_DIR"
        else
            command -v gcc >/dev/null 2>&1 || {
                echo 'Native Loong64 builds need GCC runtime discovery (install build-essential)' >&2
                return 1
            }
            runtime_dir="$(dirname "$(gcc -print-libgcc-file-name)")"
        fi
        ;;
    *)
        target_root="${LOONG64_TARGET_ROOT:-/usr/loongarch64-linux-gnu}"
        target_libdir="${LOONG64_TARGET_LIBDIR:-$target_root/lib}"
        runtime_dir="${LOONG64_GCC_RUNTIME_DIR:-/usr/lib/gcc-cross/loongarch64-linux-gnu/13}"
        ;;
esac
