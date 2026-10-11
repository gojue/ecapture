# Loong64 build and validation

eCapture supports Linux/LoongArch64 with Go's `GOARCH=loong64` on kernel 6.6
or newer. Android/loong64 is not supported. The existing Linux/Android amd64
and arm64 paths keep their Ubuntu 22.04, GCC cross-toolchain, glibc, and kernel
minimums.

## Architecture names

These names belong to different interfaces and are not interchangeable:

| Interface | Value |
| --- | --- |
| Go | `loong64` |
| Linux Kbuild | `loongarch` |
| Clang/GNU target | `loongarch64-linux-gnu` |
| libpcap canonical host | `loongarch64-unknown-linux-gnu` |
| eBPF target macro | `__TARGET_ARCH_loongarch` |

Use an Ubuntu 24.04 x86_64 host. `builder/check-build-environment.sh` rejects
another OS, release, or host architecture before libpcap or eBPF compilation.

## Toolchain and sysroot

Install LLVM/Clang/LLD 18 and the Loong64 cross sysroot:

```sh
sudo apt-get update
sudo apt-get install --yes \
  bc bison clang-18 dwarves file flex \
  libatomic1-loong64-cross libc6-dev-loong64-cross libelf-dev \
  libgcc-13-dev-loong64-cross libssl-dev linux-libc-dev-loong64-cross \
  linux-source linux-tools-common linux-tools-generic lld-18 \
  llvm-18 llvm-18-tools make pkg-config xz-utils
```

The build requires `clang-18`, `clang++-18`, `llc-18`, `ld.lld-18`, and the
versioned LLVM 18 `ar`, `ranlib`, `nm`, `strip`, `objcopy`, `objdump`, and
`readelf` tools. The single `builder/check-build-environment.sh` preflight
checks every major version and verifies target headers, `crt1.o`, `Scrt1.o`,
`rcrt1.o`, `crti.o`, `crtn.o`, static glibc, `libgcc.a`, and `libatomic.a`.

The default sysroot root is `/`, while target headers and libraries are pinned
to `/usr/loongarch64-linux-gnu` by `LOONG64_TARGET_ROOT`. This split is
required by Ubuntu's cross-glibc linker scripts, whose absolute
`/usr/loongarch64-linux-gnu/...` entries must be resolved from the filesystem
root rather than have the target prefix applied twice. The compiler runtime is
the target libgcc runtime in `/usr/lib/gcc-cross/loongarch64-linux-gnu/13`.
This is an explicit `--rtlib=libgcc` choice; it does not execute a GCC compiler
frontend. Fully replacing GNU runtime libraries with compiler-rt is outside
this support contract and must not be inferred from the LLVM-only command
chain. Override `LOONG64_SYSROOT`, `LOONG64_TARGET_ROOT`, or
`LOONG64_GCC_RUNTIME_DIR` only with an equivalent complete target
installation.

`builder/loong64-clang` always supplies:

```text
--target=loongarch64-linux-gnu -mabi=lp64d
--sysroot=/ -isystem /usr/loongarch64-linux-gnu/include
-L/usr/loongarch64-linux-gnu/lib
--gcc-install-dir=/usr/lib/gcc-cross/loongarch64-linux-gnu/13
```

For link actions it additionally supplies `--rtlib=libgcc` and the target
library/runtime `-L` paths. Those link-only flags are intentionally omitted
for `-E`, `-c`, `-S`, dependency-only, and syntax-only invocations so cgo's
`-Werror` compiler probes do not reject them as unused. Non-CO-RE eBPF builds
add the Clang 18 resource include directory for LLVM's LoongArch intrinsic
headers before compiling LLVM IR and passing it to `llc-18`.

libpcap and cgo set that wrapper as `CC`, use LLVM 18 archive tools, and pass
`-fuse-ld=lld` at link time. Go's external linker is the Clang driver wrapper;
`ld.lld-18` is never used directly as `-extld`. The final static PIE link uses
`-static -static-pie -fuse-ld=lld`; retaining `-static` preserves the existing
link contract while `-static-pie` makes the required ELF `ET_DYN` result
explicit.

## LoongArch BTF source

CO-RE never reuses the x86 or arm64 `vmlinux.h`. Build a LoongArch `vmlinux`
with BTF from Ubuntu 24.04's installed `linux-source` package:

```sh
builder/prepare-loong64-kernel.sh /path/to/extracted/linux-source
```

The script uses `ARCH=loongarch LLVM=-18`, enables DWARF5 and
`CONFIG_DEBUG_INFO_BTF`, and rejects Linux older than 6.6. During the eCapture
build, `builder/generate-loong64-vmlinux-header.sh` verifies that the input is
a LoongArch ELF containing `.BTF`, generates the header with bpftool, and
writes an ignored source record containing the kernel version, vmlinux
SHA-256, and bpftool version. CI also records the exact Ubuntu package versions
with `dpkg-query`.

## Build

Initialize the libpcap submodule, then use a configured Linux source tree. The
same tree supplies non-CO-RE headers and the LoongArch BTF-bearing vmlinux:

```sh
git submodule update --init --recursive
make clean CROSS_ARCH=loong64
KERN_HEADERS=/path/to/linux-source \
  LOONG64_VMLINUX=/path/to/linux-source/vmlinux \
  CROSS_ARCH=loong64 make env
KERN_HEADERS=/path/to/linux-source \
  LOONG64_VMLINUX=/path/to/linux-source/vmlinux \
  CROSS_ARCH=loong64 make all
```

libpcap, core/non-core bytecode, and Go intermediates are isolated below
`.build/linux-loong64/`. The generated Go asset is architecture-tagged, and
`bin/ecapture` is a compatibility copy for direct invocation. Packaging
copies the selected `.build/linux-loong64/bin/ecapture` instead of trusting the
shared path. Release archives use `linux-loong64`; Debian packages use
architecture `loong64`. The current RPM spec remains a native rpmbuild flow and
is not part of the Loong64 cross release job.

## Verification

Run the repository verifier after a verbose build:

```sh
builder/verify-loong64-artifact.sh \
  bin/ecapture \
  .build/linux-loong64/libpcap/libpcap.a \
  .build/linux-loong64/libpcap/config.log \
  /path/to/verbose-build.log
qemu-loongarch64-static bin/ecapture --help
```

It checks the LLVM 18 versions, libpcap's recorded compiler, every libpcap
archive member's ELF machine, final LoongArch ELF type, absence of an ELF
interpreter and `DT_NEEDED`, Clang's `-###` linker choice, the final ELF's LLD
18 `.comment` when stripping retained it, and obvious GNU frontend/binutil
executions in the verbose log. QEMU user mode covers only CLI startup and the
GoTLS instruction unit test.

There is no LoongArch64 E2E job. The PR Debug Loong64 job cross-builds and
checks the static artifact, then runs QEMU user-mode CLI and GoTLS instruction
smoke tests; it does not boot a LoongArch kernel or exercise eBPF load,
attachment, or capture.

## Dependency audit

The support decision is based on the pinned repository versions and their
source, not on assumed upstream support:

| Component | Audited evidence and remaining boundary |
| --- | --- |
| Go 1.26.0 | The Go platform table marks `linux/loong64` cgo-capable and supports PIE; runtime/cgo contains Loong64 assembly. The build CI exercises cgo plus external static PIE linking. |
| `github.com/cilium/ebpf` v0.22.0 | Little-endian and 64-bit build constraints include `loong64`; generated BPF examples include it. Its syscall-wrapper feature table has no LoongArch prefix, consistent with LoongArch not selecting `ARCH_HAS_SYSCALL_WRAPPER`; native load/attach remains unverified. |
| `github.com/gojue/ebpfmanager` v0.6.0 | Linux code is not restricted to amd64/arm64. Kprobe resolution first accepts the exact kallsyms symbol used by eCapture; fallback behavior remains unverified on a LoongArch kernel. |
| libpcap 1.10.4, gitlink `104271ba4a14de6743e43bcf87536786d8fddea4` | Its `config.sub` recognizes `loongarch64`; CI proves Clang 18 configuration and audits every archive member. |
| `golang.org/x/sys` v0.48.0 | Contains Linux Loong64 syscall, type, assembly, CPU, and little-endian files. |
| `golang.org/x/arch` v0.31.0 | Supplies the Loong64 decoder used to find GoTLS return instructions. Go's ABI documentation defines integer arguments in R4-R19; eCapture reads the first eight through LoongArch PT_REGS R4-R11. |
| bpftool/BTF | Header generation is from the verified LoongArch Linux 6.6+ vmlinux built in the same configured source tree, never from host x86 BTF. |
| PT_REGS/ELF | The repository's libbpf-style tracing header defines LoongArch `user_pt_regs`, arguments, return value, SP, FP, and IP. Runtime ELF checks accept `EM_LOONGARCH`; LoongArch is little-endian in the audited Go/x/sys and cilium/ebpf sources. |
| Packaging/CI/E2E | Tar/deb names use `loong64`. The independent Loong64 release job starts only after amd64/arm64 publishing succeeds, then uploads its tar/deb files and a separate `checksum-loong64-<tag>.txt`; its failure cannot block the primary release. The PR Debug Loong64 job cross-builds and runs QEMU user-mode smoke tests; there is no LoongArch E2E job. |

Without a real LoongArch64 kernel test, static PIE startup, CO-RE relocation
against runtime BTF, uprobes/kprobes, TC attachment, and capture correctness
remain unverified runtime risks.
