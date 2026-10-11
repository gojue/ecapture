#!/usr/bin/env bash

set -euo pipefail

kernel_source="${1:-}"
jobs="${JOBS:-$(nproc)}"

if [[ -z "$kernel_source" || ! -f "$kernel_source/Makefile" ]]; then
    echo "usage: $0 /path/to/linux-source" >&2
    exit 2
fi
"$(dirname "$0")/check-build-environment.sh" loong64 linux
for tool in make pahole; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing LoongArch kernel build tool: $tool" >&2
        exit 1
    }
done

kernel_version="$(make -s -C "$kernel_source" kernelversion)"
if [[ "$(printf '%s\n%s\n' 6.6 "$kernel_version" | sort -V | head -n 1)" != "6.6" ]]; then
    echo "LoongArch kernel source must be 6.6 or newer; found $kernel_version" >&2
    exit 1
fi

make -C "$kernel_source" ARCH=loongarch LLVM=-18 defconfig
# Ubuntu's 6.8 source enables a Loongson DRM driver that calls a helper absent
# from the same source package. Display support is not needed for BTF headers.
"$kernel_source/scripts/config" --file "$kernel_source/.config" \
    --enable DEBUG_INFO \
    --enable DEBUG_INFO_DWARF5 \
    --enable DEBUG_INFO_BTF \
    --disable DEBUG_INFO_NONE \
    --disable DEBUG_INFO_REDUCED \
    --disable DRM_LOONGSON
make -C "$kernel_source" ARCH=loongarch LLVM=-18 olddefconfig
make -C "$kernel_source" ARCH=loongarch LLVM=-18 -j"$jobs" vmlinux
