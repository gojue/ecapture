#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "non-CO-RE compiler tests require Linux" >&2
    exit 1
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/ecapture-nocore-cflags.XXXXXX")"
trap 'rm -rf -- "$test_dir"' EXIT

# Linux 6.19+ embeds tagged structs anonymously. Without the matching C
# dialect, Clang drops the fields, breaking both layout and member access.
cat >"$test_dir/anonymous_fields.c" <<'C'
struct filename_head {
    const char *name;
    const char *uptr;
};

struct filename {
    struct filename_head;
    char iname[32];
};

_Static_assert(__builtin_offsetof(struct filename, iname) == sizeof(struct filename_head),
    "anonymous fields must preserve the kernel structure layout");

int read_filename(struct filename *filename) { return filename->name != 0 && filename->uptr != 0; }
C

# Use the production flags and the same Clang -> LLVM IR -> BPF pipeline.
# preflight rejects unsupported hosts, targets, and kernels before compilation.
cat >"$test_dir/rules.mk" <<'MAKE'
.PHONY: check-nocore-cflags
check-nocore-cflags: preflight
	set -euo pipefail
	$(CMD_CLANG) $(EXTRA_CFLAGS_NOCORE) -c "$(NOCORE_CFLAGS_TEST_DIR)/anonymous_fields.c" -o "$(NOCORE_CFLAGS_TEST_DIR)/anonymous_fields.ll"
	$(CMD_LLC) -march=bpf -filetype=obj "$(NOCORE_CFLAGS_TEST_DIR)/anonymous_fields.ll" -o "$(NOCORE_CFLAGS_TEST_DIR)/anonymous_fields.o"
	$(CMD_STRIP) -g "$(NOCORE_CFLAGS_TEST_DIR)/anonymous_fields.o"
	$(CMD_READELF) -h "$(NOCORE_CFLAGS_TEST_DIR)/anonymous_fields.o" | grep -Eq 'Machine:.*BPF'
MAKE

make --no-print-directory -s -f Makefile -f "$test_dir/rules.mk" \
    NOCORE_CFLAGS_TEST_DIR="$test_dir" check-nocore-cflags
echo "non-CO-RE anonymous-field compilation passed"
