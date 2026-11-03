#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=builder/loong64-toolchain.sh
source "$(dirname "$0")/loong64-toolchain.sh"

kernel_source="${1:-}"
vmlinux="${2:-}"
output="${3:-}"

version_at_least() {
    local actual="$1"
    local required="$2"
    [[ "$(printf '%s\n%s\n' "$required" "$actual" | sort -V | head -n 1)" == "$required" ]]
}

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "LoongArch vmlinux.h generation requires Linux" >&2
    exit 1
fi
if [[ -z "$kernel_source" || ! -f "$kernel_source/Makefile" ]]; then
    echo "configured Linux source tree not found: ${kernel_source:-unset}" >&2
    exit 1
fi
if [[ -z "$vmlinux" ]]; then
    vmlinux="$kernel_source/vmlinux"
fi
if [[ -z "$output" || ! -f "$vmlinux" ]]; then
    echo "LoongArch vmlinux with BTF not found: ${vmlinux:-unset}" >&2
    exit 1
fi

kernel_version="$(make -s -C "$kernel_source" kernelversion)"
if ! version_at_least "$kernel_version" "6.6"; then
    echo "LoongArch BTF source must be Linux 6.6 or newer; found $kernel_version" >&2
    exit 1
fi
btf_source='LoongArch ELF with .BTF'
header_kernel_version="$kernel_version"
if [[ "$vmlinux" == /sys/kernel/btf/vmlinux ]]; then
    case "$(uname -m)" in
        loongarch64|loong64) ;;
        *) echo 'Running-kernel BTF requires a native LoongArch host' >&2; exit 1 ;;
    esac
    kernel_version="$(uname -r)"
    if ! version_at_least "${kernel_version%%-*}" 6.6; then
        echo 'Native LoongArch BTF requires kernel 6.6 or newer' >&2
        exit 1
    fi
    btf_source='native LoongArch running-kernel BTF (/sys/kernel/btf/vmlinux)'
else
    elf_header="$("llvm-readelf-$llvm_major" -h "$vmlinux")"
    if ! grep -Eq 'Machine:.*LoongArch' <<<"$elf_header"; then
        echo "BTF source is not a LoongArch ELF: $vmlinux" >&2
        exit 1
    fi
    section_headers="$("llvm-readelf-$llvm_major" -S "$vmlinux")"
    if ! grep -Eq '[[:space:]]\.BTF[[:space:]]' <<<"$section_headers"; then
        echo "LoongArch vmlinux does not contain a .BTF section: $vmlinux" >&2
        exit 1
    fi
fi
command -v bpftool >/dev/null 2>&1 || {
    echo "bpftool is required to generate vmlinux.h" >&2
    exit 1
}

mkdir -p "$(dirname "$output")"
tmp_header="$(mktemp "${TMPDIR:-/tmp}/ecapture-loong64-vmlinux.XXXXXX")"
trap 'rm -f -- "$tmp_header"' EXIT
bpftool btf dump file "$vmlinux" format c >"$tmp_header"
test -s "$tmp_header"
mv "$tmp_header" "$output"
trap - EXIT

source_manifest="${output%.h}.source"
{
    printf 'kernel_version=%s\n' "$kernel_version"
    printf 'header_kernel_version=%s\n' "$header_kernel_version"
    printf 'source=%s\n' "$btf_source"
    printf 'vmlinux_sha256=%s\n' "$(sha256sum "$vmlinux" | awk '{print $1}')"
    printf 'generator=%s\n' "$(bpftool version | head -n 1)"
} >"$source_manifest"
