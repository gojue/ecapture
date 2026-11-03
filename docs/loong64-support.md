# Loong64 build and validation

eCapture supports Linux/LoongArch64 with Go's `GOARCH=loong64` on kernel 6.6
or newer. Android/loong64 is not supported. The existing Linux/Android amd64
and arm64 paths share the Ubuntu 24.04 release runner and retain their GCC
compiler selection, LLVM 14 BPF compiler, and documented kernel minimums.
Runner upgrades still require target-kernel runtime verification; successful
static linking alone is not proof of compatibility with an older kernel.

## Architecture names

These names belong to different interfaces and are not interchangeable:

| Interface | Value |
| --- | --- |
| Go | `loong64` |
| Linux Kbuild | `loongarch` |
| Clang/GNU target | `loongarch64-linux-gnu` |
| libpcap canonical host | `loongarch64-unknown-linux-gnu` |
| eBPF target macro | `__TARGET_ARCH_loongarch` |

Use Ubuntu 24.04 x86_64 for cross-builds or Debian 13+ LoongArch64 for native builds. `builder/check-build-environment.sh` rejects
another OS, release, or host architecture before libpcap or eBPF compilation.

## Toolchain and sysroot

From an existing checkout on Ubuntu 24.04 x86_64, initialize the complete
cross-build environment with:

```sh
TARGET_ARCH=loong64 bash builder/init_env.sh
```

The initializer installs the LLVM 22.1.8 tools, target static libraries and QEMU,
initializes libpcap, and calls the existing kernel preparation script to build
a BTF-bearing `vmlinux`. Its kernel tree lives under `.build/kernel-loong64/`,
separate from other architectures. It prints the `TARGET_ARCH`, `KERN_HEADERS`
and `LOONG64_VMLINUX` exports and the build command to run next. This prepares
build inputs; it does not install or boot the target kernel.

For Ubuntu cross-builds, the initializer configures the signed
[LLVM 22 package source](https://apt.llvm.org/) and selects packages whose
upstream version is exactly 22.1.8. It verifies the repository key fingerprint
and does not execute a downloaded installer. On disposable GitHub-hosted runners,
failed system DNS resolution for `apt.llvm.org` falls back to Google DNS over
HTTPS and a job-local hosts entry, retaining TLS and package signature checks.
Native Debian uses its configured
package sources. Missing 22.1.8 packages fail initialization instead of falling
back to another toolchain version.

The build requires versioned `clang-22`, `clang++-22`, `llc-22`, `ld.lld-22`,
and LLVM 22 archive and inspection tools. The shared preflight checks every
tool's full 22.1.8 version and verifies target headers, `crt1.o`, `Scrt1.o`,
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
add the Clang 22 resource include directory for LLVM's LoongArch intrinsic
headers before compiling LLVM IR and passing it to `llc-22`.

libpcap and cgo set that wrapper as `CC`, use LLVM 22.1.8 archive tools, and pass
`-fuse-ld=lld` at link time. Go's external linker is the Clang driver wrapper;
`ld.lld-22` is never used directly as `-extld`. The final static PIE link uses
`-static -static-pie -fuse-ld=lld`; retaining `-static` preserves the existing
link contract while `-static-pie` makes the required ELF `ET_DYN` result
explicit.

## LoongArch BTF source

CO-RE never reuses the x86 or arm64 `vmlinux.h`. Build a LoongArch `vmlinux`
with BTF from Ubuntu 24.04's installed `linux-source` package:

```sh
builder/prepare-loong64-kernel.sh /path/to/extracted/linux-source
```

The script uses `ARCH=loongarch LLVM=-22`, enables DWARF5 and
`CONFIG_DEBUG_INFO_BTF`, and rejects Linux older than 6.6. During the eCapture
build, `builder/generate-loong64-vmlinux-header.sh` verifies that the input is
a LoongArch ELF containing `.BTF`, generates the header with bpftool, and
writes an ignored source record containing the kernel version, vmlinux
SHA-256, and bpftool version.

## Build helper responsibilities

These helpers are called by the shared build flow and remain necessary on
Ubuntu 24.04:

| Helper in `builder/` | Responsibility |
| --- | --- |
| `loong64-clang`, `loong64-clang++` | Select the LoongArch C/C++ target, LP64D ABI, sysroot and static runtime paths for libpcap, cgo and external linking. |
| `prepare-loong64-kernel.sh` | Configure a Linux 6.6+ LoongArch kernel and build `vmlinux` with BTF. |
| `generate-loong64-vmlinux-header.sh` | Verify the target ELF and BTF, then generate the CO-RE header during `make`. |
| `verify-loong64-artifact.sh` | Audit the final binary, libpcap archive and compiler/linker evidence. |

`init_env.sh` orchestrates installation and preparation; it reuses these
helpers. `check-build-environment.sh` validates the supported host and
toolchain before compilation.

## Build

Initialize the libpcap submodule, then use a configured Linux source tree. The
same tree supplies non-CO-RE headers and the LoongArch BTF-bearing vmlinux:

```sh
git submodule update --init --recursive
make clean TARGET_ARCH=loong64
KERN_HEADERS=/path/to/linux-source \
  LOONG64_VMLINUX=/path/to/linux-source/vmlinux \
  TARGET_ARCH=loong64 make env
KERN_HEADERS=/path/to/linux-source \
  LOONG64_VMLINUX=/path/to/linux-source/vmlinux \
  TARGET_ARCH=loong64 make all
```

libpcap, core/non-core bytecode, and Go intermediates are isolated below
`.build/linux-loong64/`. The generated Go asset is architecture-tagged, and
`bin/ecapture` is a compatibility copy for direct invocation. Packaging
copies the selected `.build/linux-loong64/bin/ecapture` instead of trusting the
shared path. Release archives use `linux-loong64`; Debian packages use
architecture `loong64`. The current RPM spec remains a native rpmbuild flow and
is not part of the shared release job. The common `release` target builds
Linux tar/deb artifacts for all architectures and Android only for amd64/arm64.

## Native Debian build

Debian 13+ LoongArch64 (kernel >= 6.6) uses LLVM/Clang/LLD 22.1.8:

```sh
bash builder/init_env.sh
# Apply the PATH, TARGET_ARCH, KERN_HEADERS and LOONG64_VMLINUX exports.
make clean && make all
bash test/build/architecture_config_test.sh
```

The initializer installs native LLVM 22 packages, bpftool and build dependencies.
The Clang wrapper drives versioned `ld.lld-22` for static PIE and retains
native glibc/libgcc; Go's `-extld` must not invoke LLD directly. Preflight
checks the validated 22.1.8 tools, and the audit checks the linker trace and
ELF linker identity. Cross-builds use the same toolchain version.

With running-kernel BTF, packaged kernel source is prepared only for non-CO-RE
headers. Without it, the kernel helper builds a BTF-bearing vmlinux. Raw BTF
is accepted only from `/sys/kernel/btf/vmlinux` on a native LoongArch host;
provenance distinguishes the BTF kernel from the header-source kernel.
Compilation against packaged headers does not prove capture on a different
running kernel. LLVM 20/21 were not tested; no compatibility claim is made
for those releases.

## Verification

Run the repository verifier after a verbose build:

```sh
builder/verify-loong64-artifact.sh \
  bin/ecapture \
  .build/linux-loong64/libpcap/libpcap.a \
  .build/linux-loong64/libpcap/config.log \
  /path/to/verbose-build.log
# Native host: bin/ecapture --help
# Cross-build host:
qemu-loongarch64-static bin/ecapture --help
```

It checks LLVM/Clang/LLD 22.1.8 on both build paths, libpcap's recorded
compiler, every archive member's ELF machine, final LoongArch static PIE,
absence of an ELF interpreter and `DT_NEEDED`, and Clang's explicit selection
of `ld.lld-22`. The final ELF must retain the matching LLD 22.1.8 identity.
The verbose build log must not execute GNU compiler/linker/archive frontends.
QEMU user mode covers only CLI startup and the GoTLS instruction unit test;
validate the cross-built artifact on a real LoongArch kernel for capture.

There is no LoongArch64 E2E job. The PR Debug Loong64 matrix entry cross-builds and
checks the static artifact, then runs QEMU user-mode CLI and GoTLS instruction
smoke tests; it does not boot a LoongArch kernel or exercise eBPF load,
attachment, or capture.

## Dedicated runner

Use a dedicated Debian 13+ LoongArch64 host with kernel >= 6.6, Go 1.26+
under `/usr/local/go`, Python 3 with Linux pidfd support, systemd, and outbound
GitHub HTTPS access. Verify the release digest and native Node executables of
the community [loong64/runner](https://github.com/loong64/runner) distribution.
Register with labels `self-hosted`, `Linux`, `loongarch64`, `ecapture` and
`--disableupdate`; install verified community updates manually while idle.

Create the ordinary `ecapture-runner` account with home `/var/lib/ecapture-runner`
and workspace `/var/lib/ecapture-runner/_work`. Keep the runner installation at
`/opt/ecapture-actions-runner` root-owned, with writable diagnostics for the
account. The `self-hosted-loong64.yml` workflow runs native TLS package unit
tests with stub assets and `CGO_ENABLED=0`, only on `master`, `v2`, `v1`
push/manual events. Root-owned hooks enforce the workflow and trusted refs;
fork/PR code is excluded. These tests do not establish capture correctness.

Before enabling the hooks, provision a compatible E2E harness at
`/opt/ecapture-e2e/source`, its matching binary at
`/opt/ecapture-e2e/artifact/ecapture`, and the source revision in
`/opt/ecapture-e2e/SOURCE_COMMIT`; retain patch/artifact hashes. Keep the bundle
and its parents root-owned and not writable by the runner. This fixed bundle
does not test the Actions checkout's SHA. Debian/LoongArch E2E needs the
corresponding harness support, workload dependencies, and verified root access
to BPF loading, uprobes/kprobes, perf events and TC attachment.

Install from the repository root:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/ecapture-e2e
sudo install -d -o root -g ecapture-runner -m 0750 /var/log/ecapture-e2e
sudo install -d -o root -g root -m 0755 /etc/ecapture-runner /usr/local/libexec
sudo install -o root -g root -m 0750 builder/runner/runner-e2e-job.sh /usr/local/libexec/ecapture-e2e-job
sudo install -o root -g root -m 0644 builder/runner/runner-e2e-finish.py /usr/local/libexec/ecapture-e2e-finish.py
sudo install -o root -g root -m 0644 builder/runner/ecapture-e2e.service /etc/systemd/system/
sudo visudo -cf builder/runner/runner-e2e.sudoers
sudo install -o root -g root -m 0440 builder/runner/runner-e2e.sudoers /etc/sudoers.d/ecapture-e2e
sudo install -o root -g root -m 0755 builder/runner/runner-job-started.sh /etc/ecapture-runner/job-started.sh
sudo install -o root -g root -m 0755 builder/runner/runner-job-completed.sh /etc/ecapture-runner/job-completed.sh
sudo install -o root -g root -m 0644 builder/runner/runner-job-cleanup.py /etc/ecapture-runner/job-cleanup.py
sudo install -o root -g root -m 0644 builder/runner/ecapture-actions-runner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ecapture-actions-runner.service
```

The dedicated-host runner service omits mount isolation for LXC compatibility
and uses `NoNewPrivileges=false`. Its sudoers file permits only
`sudo -n /usr/bin/systemctl start ecapture-e2e.service` and the matching `stop`;
do not grant general sudo or Docker access. The fixed root E2E unit retains
`NoNewPrivileges=true`. Check command status and the source/artifact identity
in `/var/log/ecapture-e2e/latest-summary.json`; an early failure can leave an
older summary. Raw captures stay root-private under `/var/log/ecapture-e2e/`.

Start/end hooks stop E2E, reap tracked job processes and clear the checkout,
task HOME/temp/Go caches and downloaded actions/tools. Startup recovers
interrupted jobs. Root E2E cleanup removes its process group, task caches and
test-owned loopback TC state; pre-existing ingress/clsact state is rejected.
Registration, installed tools, diagnostics and private reports persist.
After service changes, reload systemd and restart while idle; inspect
`systemctl status ecapture-actions-runner.service` and its journal.

Validate on Linux with `python3 test/build/runner_cleanup_test.py -v`,
`python3 test/build/runner_e2e_finish_test.py -v`, and
`actionlint -config-file .github/actionlint.yaml .github/workflows/self-hosted-loong64.yml`.
Publish the workflow before verifying GitHub dispatch; manual runs and mocked
checks do not establish that dispatch works.

## Dependency audit

The support decision is based on the pinned repository versions and their
source, not on assumed upstream support:

| Component | Audited evidence and remaining boundary |
| --- | --- |
| Go 1.26.0 | The Go platform table marks `linux/loong64` cgo-capable and supports PIE; runtime/cgo contains Loong64 assembly. The build CI exercises cgo plus external static PIE linking. |
| `github.com/cilium/ebpf` v0.22.0 | Little-endian and 64-bit build constraints include `loong64`; generated BPF examples include it. Its syscall-wrapper feature table has no LoongArch prefix, consistent with LoongArch not selecting `ARCH_HAS_SYSCALL_WRAPPER`; native load/attach remains unverified. |
| `github.com/gojue/ebpfmanager` v0.6.0 | Linux code is not restricted to amd64/arm64. Kprobe resolution first accepts the exact kallsyms symbol used by eCapture; fallback behavior remains unverified on a LoongArch kernel. |
| libpcap 1.10.4, gitlink `104271ba4a14de6743e43bcf87536786d8fddea4` | Its `config.sub` recognizes `loongarch64`; CI checks Clang 22 configuration and audits every archive member. |
| `golang.org/x/sys` v0.48.0 | Contains Linux Loong64 syscall, type, assembly, CPU, and little-endian files. |
| `golang.org/x/arch` v0.31.0 | Supplies the Loong64 decoder used to find GoTLS return instructions. Go's ABI documentation defines integer arguments in R4-R19; eCapture reads the first eight through LoongArch PT_REGS R4-R11. |
| bpftool/BTF | Header generation is from the verified LoongArch Linux 6.6+ vmlinux built in the same configured source tree, never from host x86 BTF. |
| PT_REGS/ELF | The repository's libbpf-style tracing header defines LoongArch `user_pt_regs`, arguments, return value, SP, FP, and IP. Runtime ELF checks accept `EM_LOONGARCH`; LoongArch is little-endian in the audited Go/x/sys and cilium/ebpf sources. |
| Packaging/CI/E2E | Tar/deb names use `loong64`. The shared Ubuntu 24.04 release job builds amd64, arm64 and loong64 through the same entry point and publishes successful artifacts with one checksum file. Loong64 installation/build/audit failures remove incomplete artifacts and do not block amd64/arm64 publication. The shared PR matrix adds Loong64 ELF/toolchain checks and QEMU user-mode smoke tests; there is no LoongArch E2E job. |

Without a real LoongArch64 kernel test, static PIE startup, CO-RE relocation
against runtime BTF, uprobes/kprobes, TC attachment, and capture correctness
remain unverified runtime risks.
