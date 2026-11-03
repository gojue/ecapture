#!/usr/bin/env bash

set -euo pipefail

# Each case supplies its own target and headers.
unset TARGET_ARCH CROSS_ARCH KERN_HEADERS

# Keep recursive Make paths stable when a launcher expands argv[0].
MAKE=$(command -v make)
export MAKE

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"
[[ "$(uname -s)" == Linux ]] || { echo 'Build checks require Linux' >&2; exit 1; }
loong64_build_host=0
if [[ "$(uname -s)" == "Linux" ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "$(uname -m)" == x86_64 && "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]; then
        loong64_build_host=1
    elif [[ "$(uname -m)" == loongarch64 && "${ID:-}" == debian && "${VERSION_ID:-0}" =~ ^[0-9]+$ ]] &&
        ((VERSION_ID >= 13)); then
        loong64_build_host=1
    fi
fi

assert_mapping() {
    local target="$1"
    local expected="$2"
    local output command_line_output legacy_output matching_output ignored_legacy_output
    output="$(HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH="$target" make -s print-arch-vars)"
    command_line_output="$(HOST_ARCH=x86_64 HOST_OS=Linux make -s print-arch-vars TARGET_ARCH="$target")"
    legacy_output="$(HOST_ARCH=x86_64 HOST_OS=Linux CROSS_ARCH="$target" make -s print-arch-vars)"
    matching_output="$(HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH="$target" CROSS_ARCH="$target" make -s print-arch-vars)"
    ignored_legacy_output="$(HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH="$target" CROSS_ARCH=mips64 make -s print-arch-vars)"
    if [[ "$output" != "$command_line_output" || "$output" != "$legacy_output" || "$output" != "$matching_output" || "$output" != "$ignored_legacy_output" ]]; then
        echo "$target mapping differs between target selector forms" >&2
        exit 1
    fi
    while IFS= read -r line; do
        grep -Fxq "$line" <<<"$output" || {
            echo "$target mapping missing: $line" >&2
            exit 1
        }
    done <<<"$expected"
}

assert_mapping amd64 $'GOARCH=amd64\nTARGET_ARCH=amd64\nTARGET_MACHINE_ARCH=x86_64\nLINUX_ARCH=x86\nLIBPCAP_ARCH=x86_64-pc-linux-gnu\nBPF_TARGET_TRIPLE=x86_64\nARCH_BUILD_DIR=.build/linux-amd64\nOUT_BIN=.build/linux-amd64/bin/ecapture'
assert_mapping arm64 $'GOARCH=arm64\nTARGET_ARCH=arm64\nTARGET_MACHINE_ARCH=aarch64\nLINUX_ARCH=arm64\nLIBPCAP_ARCH=aarch64-unknown-linux-gnu\nBPF_TARGET_TRIPLE=aarch64\nARCH_BUILD_DIR=.build/linux-arm64\nOUT_BIN=.build/linux-arm64/bin/ecapture'
assert_mapping loong64 $'GOARCH=loong64\nTARGET_ARCH=loong64\nTARGET_MACHINE_ARCH=loongarch64\nLINUX_ARCH=loongarch\nLIBPCAP_ARCH=loongarch64-unknown-linux-gnu\nBPF_TARGET_TRIPLE=loongarch64-linux-gnu\nCMD_CLANG=clang-22\nCMD_CXX='"$root_dir"$'/builder/loong64-clang++\nCMD_LLC=llc-22\nCMD_AR=llvm-ar-22\nCMD_RANLIB=llvm-ranlib-22\nCMD_NM=llvm-nm-22\nCMD_STRIP=llvm-strip-22\nCMD_OBJCOPY=llvm-objcopy-22\nCMD_OBJDUMP=llvm-objdump-22\nCMD_READELF=llvm-readelf-22\nCMD_LD_LLD=ld.lld-22\nKERNEL_HEADER_GEN='"$MAKE"$' ARCH=loongarch LLVM=-22 prepare V=0\nARCH_BUILD_DIR=.build/linux-loong64\nTARGET_LIBPCAP=.build/linux-loong64/libpcap/libpcap.a\nGENERATED_ASSET=assets/ebpf_probe_linux_loong64_bindata.go\nOUT_BIN=.build/linux-loong64/bin/ecapture\nLIBPCAP_LDFLAGS=-fuse-ld=lld --rtlib=libgcc -L/usr/lib/gcc-cross/loongarch64-linux-gnu/13\nGO_EXTLDFLAGS=-static -static-pie -fuse-ld=lld --rtlib=libgcc -L/usr/lib/gcc-cross/loongarch64-linux-gnu/13'

native_mapping="$(HOST_ARCH=x86_64 HOST_OS=Linux make -s print-arch-vars)"
grep -Fxq 'GOARCH=amd64' <<<"$native_mapping"
grep -Fxq 'KERNEL_HEADER_GEN=whoami' <<<"$native_mapping"
explicit_native_mapping="$(HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH=amd64 make -s print-arch-vars)"
grep -Fq 'make ARCH=x86' <<<"$explicit_native_mapping"
release_env="$(HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH=arm64 CROSS_ARCH=amd64 make -s -f builder/Makefile.release env)"
grep -Fq 'TARGET_ARCH              arm64' <<<"$release_env"
grep -Fq 'SELECTED_TARGET_ARCH     arm64' <<<"$release_env"
legacy_release_env="$(HOST_ARCH=x86_64 HOST_OS=Linux CROSS_ARCH=arm64 make -s -f builder/Makefile.release env)"
grep -Fq 'TARGET_ARCH              arm64' <<<"$legacy_release_env"
grep -Fq 'SELECTED_TARGET_ARCH     arm64' <<<"$legacy_release_env"
legacy_release_cli="$(HOST_ARCH=x86_64 HOST_OS=Linux make -s -f builder/Makefile.release env CROSS_ARCH=arm64)"
grep -Fq 'TARGET_ARCH              arm64' <<<"$legacy_release_cli"
override_release_cli="$(HOST_ARCH=x86_64 HOST_OS=Linux make -s -f builder/Makefile.release env TARGET_ARCH=arm64 CROSS_ARCH=amd64)"
grep -Fq 'SELECTED_TARGET_ARCH     arm64' <<<"$override_release_cli"

for target in amd64 arm64; do
    env_output="$(HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH="$target" make -s env)"
    if grep -q '^LOONG64_' <<<"$env_output"; then
        echo "$target environment unexpectedly displays Loong64-only variables" >&2
        exit 1
    fi
    grep -Fq 'GO_EXTLDFLAGS            -static' <<<"$env_output"
done
# An installed source archive must not make KERN_HEADERS and its default path recursive.
loong_env="$(HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH=loong64 make -s env \
    LINUX_SOURCE_FILE=/tmp/linux-source-6.8.tar.bz2)"
grep -Fq 'LINUX_SOURCE_PATH        /tmp/linux-source-6.8' <<<"$loong_env"
grep -Fq 'KERN_SRC_PATH            /tmp/linux-source-6.8' <<<"$loong_env"
grep -Fq 'LOONG64_SYSROOT          /' <<<"$loong_env"
grep -Fq 'LOONG64_TARGET_ROOT      /usr/loongarch64-linux-gnu' <<<"$loong_env"
grep -Fq 'LOONG64_GCC_RUNTIME_DIR  /usr/lib/gcc-cross/loongarch64-linux-gnu/13' <<<"$loong_env"
grep -Fq 'CGO_LINK_FLAGS := -static' variables.mk
grep -Fq 'CGO_LDFLAGS=' functions.mk
grep -Fq '$(CGO_LINK_FLAGS)' functions.mk

loong_mapping="$(HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH=loong64 make -s print-arch-vars)"
grep -Fxq "CMD_CC=$root_dir/builder/loong64-clang" <<<"$loong_mapping"

grep -Fq '$(CMD_CP) $(OUT_BIN) $(TAR_DIR)/ecapture' functions.mk
grep -Fq '$(CMD_CP) $(OUT_BIN) $(BUILD_DIR)/usr/local/bin/ecapture' builder/Makefile.release
grep -Fq 'LD="$(CMD_CC_PREFIX)$(CMD_CC)"' Makefile
grep -Fq -- '--disable DRM_LOONGSON' builder/prepare-loong64-kernel.sh
grep -Fq -- '--gcc-install-dir="$runtime_dir"' builder/loong64-clang
grep -Fq 'section_headers="$("llvm-readelf-$llvm_major" -S "$vmlinux")"' \
    builder/generate-loong64-vmlinux-header.sh
grep -Fq 'archive="$(realpath "$archive")"' builder/verify-loong64-artifact.sh

forbidden_tool_pattern="$(
    sed -n "s/^    forbidden_tool_pattern='\\(.*\\)'$/\\1/p" \
        builder/verify-loong64-artifact.sh
)"
if [[ -z "$forbidden_tool_pattern" ]]; then
    echo "unable to load the forbidden Loong64 build tool pattern" >&2
    exit 1
fi
if grep -Eq "$forbidden_tool_pattern" <<<'        --without-gcc --with-pcap=linux \\'; then
    echo "libpcap --without-gcc option was mistaken for a GCC invocation" >&2
    exit 1
fi
grep -Eq "$forbidden_tool_pattern" <<<'loongarch64-linux-gnu-gcc -c conftest.c'
grep -Eq "$forbidden_tool_pattern" <<<'/usr/bin/ld -static conftest.o'

if HOST_ARCH=x86_64 HOST_OS=Linux CROSS_ARCH=mips64 make -s print-arch-vars >/dev/null 2>&1; then
    echo "unsupported CROSS_ARCH unexpectedly fell through" >&2
    exit 1
fi
if HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH=mips64 make -s print-arch-vars >/dev/null 2>&1; then
    echo "unsupported TARGET_ARCH unexpectedly fell through" >&2
    exit 1
fi
if HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH='amd64 arm64' make -s print-arch-vars >/dev/null 2>&1; then
    echo "multiple target architectures unexpectedly succeeded" >&2
    exit 1
fi
override_mapping="$(HOST_ARCH=x86_64 HOST_OS=Linux CROSS_ARCH=amd64 make -s print-arch-vars TARGET_ARCH=arm64)"
grep -Fxq 'TARGET_ARCH=arm64' <<<"$override_mapping"
grep -Fxq 'TARGET_MACHINE_ARCH=aarch64' <<<"$override_mapping"
empty_override_mapping="$(HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH= CROSS_ARCH=arm64 make -s print-arch-vars)"
grep -Fxq 'TARGET_ARCH=amd64' <<<"$empty_override_mapping"
empty_override_cli="$(HOST_ARCH=x86_64 HOST_OS=Linux make -s print-arch-vars TARGET_ARCH= CROSS_ARCH=arm64)"
grep -Fxq 'TARGET_ARCH=amd64' <<<"$empty_override_cli"
if HOST_ARCH=x86_64 HOST_OS=Linux TARGET_ARCH=loong64 ANDROID=1 make -s print-arch-vars >/dev/null 2>&1; then
    echo "unsupported TARGET_ARCH Android/loong64 combination unexpectedly succeeded" >&2
    exit 1
fi

# Keep real startup/BTF regressions separate from the mocked tools below.
# The subshell owns its temporary files and cannot leak test overrides.
check_native_loong64() (
    builder/check-build-environment.sh loong64 linux
    implicit="$(env -u TARGET_ARCH -u CROSS_ARCH make -s print-arch-vars)"
    explicit="$(TARGET_ARCH=loong64 make -s print-arch-vars)"
    grep -Fxq 'GOARCH=loong64' <<<"$implicit"
    grep -Fxq 'GOARCH=loong64' <<<"$explicit"
    native_env="$(env -u TARGET_ARCH -u CROSS_ARCH make -s env)"
    grep -Fq 'LOONG64_TARGET_ROOT      /usr' <<<"$native_env"
    grep -Fq 'LOONG64_TARGET_LIBDIR    /usr/lib/loongarch64-linux-gnu' <<<"$native_env"
    runtime="$(dirname "$(gcc -print-libgcc-file-name)")"
    grep -Fq "LOONG64_GCC_RUNTIME_DIR  $runtime" <<<"$native_env"
    pinned_env="$(make -s env LOONG64_LLVM_VERSION=17 LOONG64_LINKER=bfd)"
    grep -Fq 'LOONG64_LLVM_VERSION     22' <<<"$pinned_env"
    grep -Fq 'LOONG64_LINKER           lld' <<<"$pinned_env"

    tmp="$(mktemp -d "${TMPDIR:-/tmp}/ecapture-native-check.XXXXXX")"
    trap 'rm -rf -- "$tmp"' EXIT
    mkdir -p "$tmp/bin" "$tmp/kernel"
    # Exercise real static-glibc TLS relocations and repeated startup with LLD 22.
    cat > "$tmp/libc.c" <<'EOF'
#include <stdlib.h>
int main(void) {
    void *p = malloc(64);
    if (!p) return 1;
    free(p);
    return 0;
}
EOF
    builder/loong64-clang -O0 -static -static-pie -fuse-ld=lld "$tmp/libc.c" -o "$tmp/libc"
    for attempt in {1..30}; do "$tmp/libc" || { echo "Static PIE startup $attempt failed" >&2; exit 1; }; done
    elf_header="$(llvm-readelf-22 -h "$tmp/libc")"
    grep -Eq 'Type:.*DYN' <<<"$elf_header"
    grep -Eq 'Machine:.*LoongArch' <<<"$elf_header"
    program_headers=$(llvm-readelf-22 -l "$tmp/libc")
    dynamic_section=$(llvm-readelf-22 -d "$tmp/libc")
    if grep -q INTERP <<<"$program_headers" || grep -q NEEDED <<<"$dynamic_section"; then
        echo "Native libc test must be static PIE without shared dependencies" >&2; exit 1
    fi
    trace=$(builder/loong64-clang -### -static -static-pie -x c /dev/null -o /dev/null 2>&1)
    grep -Fq "\"$(command -v ld.lld-22)\"" <<<"$trace"
    printf 'kernelversion:\n\t@echo 6.12.0\n' > "$tmp/kernel/Makefile"
    printf 'preserved header\n' > "$tmp/vmlinux.h"
    cat > "$tmp/bin/uname" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    -s) echo Linux ;;
    -m) echo "${TEST_HOST_ARCH:-loongarch64}" ;;
    -r) echo "${TEST_HOST_KERNEL:-6.6.0}" ;;
    *) exit 2 ;;
esac
EOF
    chmod +x "$tmp/bin/uname"
    expect_rejected() {
        if "$@" > "$tmp/rejection.log" 2>&1; then
            echo 'An unsupported native build input was accepted' >&2
            exit 1
        fi
    }
    expect_rejected env TEST_HOST_KERNEL=6.5.99 PATH="$tmp/bin:$PATH" \
        builder/check-build-environment.sh loong64 linux
    grep -q 'too old' "$tmp/rejection.log"
    expect_rejected env LOONG64_TARGET_LIBDIR="$tmp/missing-libraries" \
        builder/check-build-environment.sh loong64 linux
    grep -q 'incomplete Loong64 target root' "$tmp/rejection.log"
    expect_rejected builder/check-build-environment.sh loong64 android
    expect_rejected env TEST_HOST_ARCH=x86_64 PATH="$tmp/bin:$PATH" \
        builder/generate-loong64-vmlinux-header.sh "$tmp/kernel" /sys/kernel/btf/vmlinux "$tmp/vmlinux.h"
    grep -q 'requires a native LoongArch host' "$tmp/rejection.log"
    expect_rejected env TEST_HOST_KERNEL=6.5.99 PATH="$tmp/bin:$PATH" \
        builder/generate-loong64-vmlinux-header.sh "$tmp/kernel" /sys/kernel/btf/vmlinux "$tmp/vmlinux.h"
    grep -q 'requires kernel 6.6' "$tmp/rejection.log"
    # Arbitrary raw BTF files must not bypass the cross-build ELF architecture check.
    printf 'not an ELF\n' > "$tmp/untrusted-btf"
    expect_rejected builder/generate-loong64-vmlinux-header.sh \
        "$tmp/kernel" "$tmp/untrusted-btf" "$tmp/vmlinux.h"
    grep -Fxq 'preserved header' "$tmp/vmlinux.h"
    echo 'Native Loong64 configuration and BTF boundary checks passed'
)
if [[ "$loong64_build_host" == 1 ]]; then
    case "$(uname -m)" in
        loongarch64|loong64) check_native_loong64 ;;
    esac
fi

fake_tools="$(mktemp -d "${TMPDIR:-/tmp}/ecapture-llvm-version-test.XXXXXX")"
trap 'rm -rf -- "$fake_tools"' EXIT

fake_sysroot="$fake_tools/sysroot"
fake_target_root="$fake_tools/loongarch64-linux-gnu"
fake_runtime="$fake_tools/runtime"
export LOONG64_TARGET_LIBDIR="$fake_target_root/lib"
mkdir -p "$fake_sysroot" "$fake_target_root/include" "$fake_target_root/lib" "$fake_runtime"
touch "$fake_target_root/include/stdio.h"
for file in crt1.o Scrt1.o rcrt1.o crti.o crtn.o libc.a; do
    touch "$fake_target_root/lib/$file"
done
for file in crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o libgcc.a libatomic.a; do
    touch "$fake_runtime/$file"
done

for tool in clang-22 clang++-22; do
    cat >"$fake_tools/$tool" <<'EOF'
#!/bin/sh
for arg do
    if [ "$arg" = "-dumpmachine" ]; then
        printf '%s\n' loongarch64-unknown-linux-gnu
        exit 0
    fi
done
printf '%s\n' 'Debian clang version 22.1.8'
EOF
    chmod +x "$fake_tools/$tool"
done
for tool in llc-22 llvm-ar-22 llvm-ranlib-22 llvm-strip-22 llvm-objcopy-22 llvm-objdump-22 llvm-readelf-22; do
    printf '#!/bin/sh\necho "%s version 22.1.8"\n' "$tool" >"$fake_tools/$tool"
    chmod +x "$fake_tools/$tool"
done
printf '#!/bin/sh\necho "Debian LLD 22.1.8"\n' >"$fake_tools/ld.lld-22"
chmod +x "$fake_tools/ld.lld-22"
cat >"$fake_tools/llvm-nm-22" <<'EOF'
#!/bin/sh
printf '%s\n' 'llvm-nm, compatible with GNU nm' 'Debian LLVM version 22.1.8'
EOF
chmod +x "$fake_tools/llvm-nm-22"

if [[ "$loong64_build_host" == "1" ]]; then
    PATH="$fake_tools:/usr/bin:/bin" \
        LOONG64_SYSROOT="$fake_sysroot" \
        LOONG64_TARGET_ROOT="$fake_target_root" \
        LOONG64_GCC_RUNTIME_DIR="$fake_runtime" \
        builder/check-build-environment.sh loong64 linux
elif PATH="$fake_tools:/usr/bin:/bin" \
    LOONG64_SYSROOT="$fake_sysroot" \
    LOONG64_TARGET_ROOT="$fake_target_root" \
    LOONG64_GCC_RUNTIME_DIR="$fake_runtime" \
    builder/check-build-environment.sh loong64 linux >/dev/null 2>&1; then
    echo "unsupported Loong64 build host unexpectedly passed preflight" >&2
    exit 1
fi

wrapper_trace="$(
    PATH="$fake_tools:/usr/bin:/bin" \
        LOONG64_SYSROOT="$fake_sysroot" \
        LOONG64_TARGET_ROOT="$fake_target_root" \
        LOONG64_GCC_RUNTIME_DIR="$fake_runtime" \
        LOONG64_TOOLCHAIN_TRACE=1 \
        builder/loong64-clang -c conftest.c 2>&1
)"
grep -Fq -- "--sysroot=$fake_sysroot" <<<"$wrapper_trace"
grep -Fq -- "-isystem $fake_target_root/include" <<<"$wrapper_trace"
if grep -Fq -- '--rtlib=libgcc' <<<"$wrapper_trace"; then
    echo "compile-only Loong64 wrapper invocation unexpectedly contains link flags" >&2
    exit 1
fi

wrapper_link_trace="$(
    PATH="$fake_tools:/usr/bin:/bin" \
        LOONG64_SYSROOT="$fake_sysroot" \
        LOONG64_TARGET_ROOT="$fake_target_root" \
        LOONG64_GCC_RUNTIME_DIR="$fake_runtime" \
        LOONG64_TOOLCHAIN_TRACE=1 \
        builder/loong64-clang conftest.c -o conftest 2>&1
)"
grep -Fq -- "-L$fake_target_root/lib" <<<"$wrapper_link_trace"
grep -Fq -- '--rtlib=libgcc' <<<"$wrapper_link_trace"
grep -Fq -- "--ld-path=$fake_tools/ld.lld-22" <<<"$wrapper_link_trace"
if LOONG64_CLANG_DRIVER=clang-17 builder/loong64-clang -c conftest.c >/dev/null 2>&1; then
    echo "Loong64 wrapper accepted an unsupported compiler" >&2
    exit 1
fi

grep -Fq 'CLANG_SYSTEM_INCLUDE = $(shell $(CMD_CLANG) -print-file-name=include)' variables.mk
grep -Fq -- '-xc -g -isystem $(CLANG_SYSTEM_INCLUDE)' variables.mk
grep -Fq 'set -o pipefail' Makefile
grep -Fq '$(CMD_GO) build' functions.mk
grep -Fq -- "-extldflags '\$(GO_EXTLDFLAGS)'" functions.mk
if grep -Fq -- "-extldflags='\$(GO_EXTLDFLAGS)'" functions.mk; then
    echo "Go external linker flags use unsupported key=value quoting" >&2
    exit 1
fi
grep -Fq -- '-o $(OUT_BIN) || exit 1' functions.mk

# Both native and cross preflight must reject an unvalidated patch.
if [[ "$loong64_build_host" == 1 ]]; then
    printf '#!/bin/sh\necho "Debian LLD 22.1.7"\n' > "$fake_tools/ld.lld-22"
    if PATH="$fake_tools:/usr/bin:/bin" \
        LOONG64_SYSROOT="$fake_sysroot" LOONG64_TARGET_ROOT="$fake_target_root" \
        LOONG64_GCC_RUNTIME_DIR="$fake_runtime" \
        builder/check-build-environment.sh loong64 linux >/dev/null 2>&1; then
        echo 'Unvalidated LLVM patch unexpectedly passed' >&2
        exit 1
    fi
fi

for tool in "$fake_tools"/*-22; do
    printf '#!/bin/sh\necho "%s version 17.0.0"\n' "$tool" >"$tool"
    chmod +x "$tool"
done
if [[ "$loong64_build_host" == "1" ]]; then
    if PATH="$fake_tools:/usr/bin:/bin" \
        LOONG64_SYSROOT="$fake_sysroot" \
        LOONG64_TARGET_ROOT="$fake_target_root" \
        LOONG64_GCC_RUNTIME_DIR="$fake_runtime" \
        builder/check-build-environment.sh loong64 linux >/dev/null 2>&1; then
        echo "LLVM 17 unexpectedly passed the Loong64 major-version check" >&2
        exit 1
    fi
fi

fake_uname="$fake_tools/uname"
cat >"$fake_uname" <<'EOF'
#!/bin/sh
case "$1" in
    -s) printf '%s\n' "${FAKE_UNAME_S:-Linux}" ;;
    -m) printf '%s\n' "${FAKE_UNAME_M:-x86_64}" ;;
    -r) printf '%s\n' "${FAKE_UNAME_R:-6.6.0}" ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$fake_uname"

if FAKE_UNAME_S=Darwin PATH="$fake_tools:/usr/bin:/bin" \
    builder/check-build-environment.sh amd64 linux >/dev/null 2>&1; then
    echo "unsupported build host unexpectedly passed preflight" >&2
    exit 1
fi
if FAKE_UNAME_R=4.17.0 PATH="$fake_tools:/usr/bin:/bin" \
    builder/check-build-environment.sh amd64 linux >/dev/null 2>&1; then
    echo "kernel below the amd64 minimum unexpectedly passed preflight" >&2
    exit 1
fi
if PATH="$fake_tools:/usr/bin:/bin" \
    builder/check-build-environment.sh amd64 plan9 >/dev/null 2>&1; then
    echo "unsupported target OS unexpectedly passed preflight" >&2
    exit 1
fi

printf 'Architecture build configuration checks passed\n'
