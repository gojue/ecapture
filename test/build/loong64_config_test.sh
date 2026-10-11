#!/usr/bin/env bash

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"
loong64_build_host=0
if [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]; then
        loong64_build_host=1
    fi
fi

assert_mapping() {
    local target="$1"
    local expected="$2"
    local output
    output="$(HOST_ARCH=x86_64 HOST_OS=Linux CROSS_ARCH="$target" make -s print-arch-vars)"
    while IFS= read -r line; do
        grep -Fxq "$line" <<<"$output" || {
            echo "$target mapping missing: $line" >&2
            exit 1
        }
    done <<<"$expected"
}

assert_mapping amd64 $'GOARCH=amd64\nTARGET_ARCH=x86_64\nLINUX_ARCH=x86\nLIBPCAP_ARCH=x86_64-pc-linux-gnu\nBPF_TARGET_TRIPLE=x86_64\nARCH_BUILD_DIR=.build/linux-amd64\nOUT_BIN=.build/linux-amd64/bin/ecapture'
assert_mapping arm64 $'GOARCH=arm64\nTARGET_ARCH=aarch64\nLINUX_ARCH=arm64\nLIBPCAP_ARCH=aarch64-unknown-linux-gnu\nBPF_TARGET_TRIPLE=aarch64\nARCH_BUILD_DIR=.build/linux-arm64\nOUT_BIN=.build/linux-arm64/bin/ecapture'
assert_mapping loong64 $'GOARCH=loong64\nTARGET_ARCH=loongarch64\nLINUX_ARCH=loongarch\nLIBPCAP_ARCH=loongarch64-unknown-linux-gnu\nBPF_TARGET_TRIPLE=loongarch64-linux-gnu\nCMD_CLANG=clang-18\nCMD_CXX='"$root_dir"$'/builder/loong64-clang++\nCMD_LLC=llc-18\nCMD_AR=llvm-ar-18\nCMD_RANLIB=llvm-ranlib-18\nCMD_NM=llvm-nm-18\nCMD_STRIP=llvm-strip-18\nCMD_OBJCOPY=llvm-objcopy-18\nCMD_OBJDUMP=llvm-objdump-18\nCMD_READELF=llvm-readelf-18\nCMD_LD_LLD=ld.lld-18\nKERNEL_HEADER_GEN=make ARCH=loongarch LLVM=-18 prepare V=0\nARCH_BUILD_DIR=.build/linux-loong64\nTARGET_LIBPCAP=.build/linux-loong64/libpcap/libpcap.a\nGENERATED_ASSET=assets/ebpf_probe_linux_loong64_bindata.go\nOUT_BIN=.build/linux-loong64/bin/ecapture\nLIBPCAP_LDFLAGS=-fuse-ld=lld --rtlib=libgcc -L/usr/lib/gcc-cross/loongarch64-linux-gnu/13\nGO_EXTLDFLAGS=-static -static-pie -fuse-ld=lld --rtlib=libgcc -L/usr/lib/gcc-cross/loongarch64-linux-gnu/13'

for target in amd64 arm64; do
    env_output="$(HOST_ARCH=x86_64 HOST_OS=Linux CROSS_ARCH="$target" make -s env)"
    if grep -q '^LOONG64_' <<<"$env_output"; then
        echo "$target environment unexpectedly displays Loong64-only variables" >&2
        exit 1
    fi
    grep -Fq 'GO_EXTLDFLAGS            -static' <<<"$env_output"
done
loong_env="$(HOST_ARCH=x86_64 HOST_OS=Linux CROSS_ARCH=loong64 make -s env)"
grep -Fq 'LOONG64_SYSROOT          /' <<<"$loong_env"
grep -Fq 'LOONG64_TARGET_ROOT      /usr/loongarch64-linux-gnu' <<<"$loong_env"
grep -Fq 'LOONG64_GCC_RUNTIME_DIR  /usr/lib/gcc-cross/loongarch64-linux-gnu/13' <<<"$loong_env"
grep -Fq 'CGO_LINK_FLAGS := -static' variables.mk
grep -Fq 'CGO_LDFLAGS=' functions.mk
grep -Fq '$(CGO_LINK_FLAGS)' functions.mk

loong_mapping="$(HOST_ARCH=x86_64 HOST_OS=Linux CROSS_ARCH=loong64 make -s print-arch-vars)"
grep -Fxq "CMD_CC=$root_dir/builder/loong64-clang" <<<"$loong_mapping"

grep -Fq '$(CMD_CP) $(OUT_BIN) $(TAR_DIR)/ecapture' functions.mk
grep -Fq '$(CMD_CP) $(OUT_BIN) $(BUILD_DIR)/usr/local/bin/ecapture' builder/Makefile.release
grep -Fq 'LD="$(CMD_CC_PREFIX)$(CMD_CC)"' Makefile
grep -Fq -- '--disable DRM_LOONGSON' builder/prepare-loong64-kernel.sh
grep -Fq -- '--gcc-install-dir="$runtime_dir"' builder/loong64-clang
grep -Fq 'section_headers="$(llvm-readelf-18 -S "$vmlinux")"' \
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
if HOST_ARCH=x86_64 HOST_OS=Linux CROSS_ARCH=loong64 ANDROID=1 make -s print-arch-vars >/dev/null 2>&1; then
    echo "unsupported Android/loong64 combination unexpectedly succeeded" >&2
    exit 1
fi

fake_tools="$(mktemp -d "${TMPDIR:-/tmp}/ecapture-llvm-version-test.XXXXXX")"
trap 'rm -rf -- "$fake_tools"' EXIT

fake_sysroot="$fake_tools/sysroot"
fake_target_root="$fake_tools/loongarch64-linux-gnu"
fake_runtime="$fake_tools/runtime"
mkdir -p "$fake_sysroot" "$fake_target_root/include" "$fake_target_root/lib" "$fake_runtime"
touch "$fake_target_root/include/stdio.h"
for file in crt1.o Scrt1.o rcrt1.o crti.o crtn.o libc.a; do
    touch "$fake_target_root/lib/$file"
done
for file in crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o libgcc.a libatomic.a; do
    touch "$fake_runtime/$file"
done

for tool in clang-18 clang++-18; do
    cat >"$fake_tools/$tool" <<'EOF'
#!/bin/sh
for arg do
    if [ "$arg" = "-dumpmachine" ]; then
        printf '%s\n' loongarch64-unknown-linux-gnu
        exit 0
    fi
done
printf '%s\n' 'Debian clang version 18.1.3'
EOF
    chmod +x "$fake_tools/$tool"
done
for tool in llc-18 llvm-ar-18 llvm-ranlib-18 llvm-strip-18 llvm-objcopy-18 llvm-objdump-18 llvm-readelf-18; do
    printf '#!/bin/sh\necho "%s version 18.1.3"\n' "$tool" >"$fake_tools/$tool"
    chmod +x "$fake_tools/$tool"
done
printf '#!/bin/sh\necho "Debian LLD 18.1.3"\n' >"$fake_tools/ld.lld-18"
chmod +x "$fake_tools/ld.lld-18"
cat >"$fake_tools/llvm-nm-18" <<'EOF'
#!/bin/sh
printf '%s\n' 'llvm-nm, compatible with GNU nm' 'Debian LLVM version 18.1.3'
EOF
chmod +x "$fake_tools/llvm-nm-18"

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
if LOONG64_CLANG_DRIVER=clang-17 builder/loong64-clang -c conftest.c >/dev/null 2>&1; then
    echo "Loong64 wrapper accepted a non-LLVM-18 compiler" >&2
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

for tool in clang-18 clang++-18 llc-18 ld.lld-18 llvm-ar-18 llvm-ranlib-18 llvm-nm-18 llvm-strip-18 llvm-objcopy-18 llvm-objdump-18 llvm-readelf-18; do
    printf '#!/bin/sh\necho "%s version 17.0.0"\n' "$tool" >"$fake_tools/$tool"
    chmod +x "$fake_tools/$tool"
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

printf 'Loong64 build configuration checks passed\n'
