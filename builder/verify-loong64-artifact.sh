#!/usr/bin/env bash

set -euo pipefail

binary="${1:-}"
archive="${2:-}"
config_log="${3:-}"
build_log="${4:-}"

if [[ -z "$binary" || -z "$archive" || -z "$config_log" ]]; then
    echo "usage: $0 <ecapture> <libpcap.a> <config.log> [verbose-build.log]" >&2
    exit 2
fi
for required_file in "$binary" "$archive" "$config_log"; do
    if [[ ! -f "$required_file" ]]; then
        echo "required Loong64 build artifact not found: $required_file" >&2
        exit 1
    fi
done
archive="$(realpath "$archive")"
"$(dirname "$0")/check-build-environment.sh" loong64 linux

elf_header="$(llvm-readelf-18 -h "$binary")"
grep -Eq 'Machine:.*LoongArch' <<<"$elf_header"
grep -Eq 'Type:.*DYN' <<<"$elf_header"
program_headers="$(llvm-readelf-18 -l "$binary")"
if grep -q 'INTERP' <<<"$program_headers"; then
    echo "Loong64 binary unexpectedly has a dynamic interpreter" >&2
    exit 1
fi
dynamic_section="$(llvm-readelf-18 -d "$binary" 2>/dev/null || true)"
if grep -q 'NEEDED' <<<"$dynamic_section"; then
    echo "Loong64 binary unexpectedly has dynamic dependencies" >&2
    exit 1
fi
if ! grep -Eq 'clang version 18|clang-18' "$config_log"; then
    echo "libpcap config.log does not prove Clang 18 was used" >&2
    exit 1
fi
if ! grep -Eq "^CC='.*builder/loong64-clang'" "$config_log"; then
    echo "libpcap config.log did not record the Loong64 Clang wrapper as CC" >&2
    exit 1
fi
for assignment in "AR='llvm-ar-18'" "RANLIB='llvm-ranlib-18'"; do
    if ! grep -Fxq "$assignment" "$config_log"; then
        echo "libpcap config.log is missing LLVM tool assignment: $assignment" >&2
        exit 1
    fi
done

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ecapture-libpcap-loong64.XXXXXX")"
trap 'rm -rf -- "$tmp_dir"' EXIT
(
    cd "$tmp_dir"
    llvm-ar-18 x "$archive"
)
found_object=0
while IFS= read -r object; do
    found_object=1
    object_header="$(llvm-readelf-18 -h "$object")"
    if ! grep -Eq 'Machine:.*LoongArch' <<<"$object_header"; then
        echo "libpcap contains a non-LoongArch object: $object" >&2
        exit 1
    fi
done < <(find "$tmp_dir" -type f -name '*.o' -print)
if [[ "$found_object" != "1" ]]; then
    echo "libpcap archive contains no object files" >&2
    exit 1
fi

link_trace="$("$(dirname "$0")/loong64-clang" -### -fuse-ld=lld -static -static-pie -x c /dev/null -o /dev/null 2>&1 || true)"
if ! grep -Eq 'ld\.lld-18|/ld\.lld' <<<"$link_trace"; then
    echo "Clang driver trace does not select LLD" >&2
    exit 1
fi
elf_comment="$(llvm-readelf-18 -p .comment "$binary" 2>/dev/null || true)"
if grep -Eq 'Linker: LLD 18' <<<"$elf_comment"; then
    echo "LLD 18 recorded in final ELF .comment"
else
    echo "final ELF has no retained LLD 18 .comment; Clang -### trace proves the selected linker"
fi

if [[ -n "$build_log" ]]; then
    if [[ ! -f "$build_log" ]]; then
        echo "verbose build log not found: $build_log" >&2
        exit 1
    fi
    forbidden_tool_pattern='^[[:space:]]*([^[:space:]]*/)?([[:alnum:]_.][[:alnum:]_.-]*-)?(gcc|g\+\+|ld|ar|ranlib)([[:space:]]|$)'
    if grep -Eq "$forbidden_tool_pattern" "$build_log"; then
        echo "verbose Loong64 build log executed a forbidden GNU frontend/binutil" >&2
        exit 1
    fi
fi
