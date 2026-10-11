# eCapture build and verification guide for coding agents

Read this guide before building, generating, formatting, linting, testing,
changing CI, or reporting verification. Repository-wide rules in
`../../AGENTS.md` take precedence.

## Authority and platform boundary

Current build facts come from `go.mod`, `Makefile`, `variables.mk`,
`functions.mk`, `.github/workflows/`, and `test/e2e/README.md`.

- Compile, link, lint, test, generate eBPF assets, and run only on Linux.
- Android artifacts are built on Linux; do not invent a macOS or
  `GOOS=android` build flow.
- macOS and Windows are limited to editing, direct formatting tools, and
  read-only checks. Do not invoke Makefile targets there.
- Runtime targets are Linux/Android x86_64 kernel >= 4.18 and aarch64 kernel
  >= 5.5, plus Linux LoongArch64 kernel >= 6.6. Android/loong64 is unsupported.
- Probe execution needs root or documented capabilities. The maintained E2E
  shell harness explicitly requires EUID 0, so capabilities alone do not
  satisfy it.
- `make env` prints computed variables and versions; it is not proof that all
  dependencies, headers, submodules, or runtime capabilities are usable.

If a remote builder is described in an optional `AGENTS.local.md`, verify its
checkout and synchronization before use. Otherwise ask for an execution
environment rather than assuming a host or path.

## Toolchain and prerequisites

Key build requirements:

- Go 1.26.0 or newer;
- GNU Make and Bash, Git, `ar`, `file`, GNU sed, and pkg-config;
- Clang >= 9 plus `llc` and `bpftool` (CI uses LLVM/Clang 14);
- GCC or an architecture cross-GCC as needed;
- libelf development files and suitable Linux headers/source;
- the recursive `lib/libpcap/` submodule.

CI currently uses golangci-lint v2.13.2 and also installs `llvm-strip`.
`llvm-strip` is not currently invoked by the normal build recipe, so do not
describe it as a universal hard dependency.

Initialize dependencies on Linux:

```sh
git submodule update --init --recursive
```

Loong64 is a separate Ubuntu 24.04 x86_64 cross-build path. It requires the
versioned LLVM 18 commands (`clang-18`, `clang++-18`, `llc-18`, `ld.lld-18`,
and the `llvm-{ar,ranlib,nm,strip,objcopy,objdump,readelf}-18` tools),
`libc6-dev-loong64-cross`, `linux-libc-dev-loong64-cross`,
`libgcc-13-dev-loong64-cross`, and `libatomic1-loong64-cross`. The checked-in
wrapper always selects `loongarch64-linux-gnu`, LP64D, the target sysroot, and
the target libgcc runtime; it never invokes a GCC frontend. The final link is
driven by that Clang wrapper with `-fuse-ld=lld`, not by calling `ld.lld-18`
directly. See `../loong64-support.md` for the complete package and audit matrix.
On Ubuntu, `LOONG64_SYSROOT=/` is intentional: the cross-glibc linker scripts
contain absolute `/usr/loongarch64-linux-gnu/...` paths. The wrapper separately
pins `LOONG64_TARGET_ROOT=/usr/loongarch64-linux-gnu` for target headers and
libraries, preventing LLD from applying the target prefix twice.
Link-only runtime and library flags are omitted for preprocessing and
compile-only wrapper invocations so cgo's `-Werror` probes remain valid. The
non-CO-RE path explicitly adds Clang 18's resource include directory; this is
where LLVM provides the LoongArch `larchintrin.h` required by Linux headers.
The Loong64 Go external-link flags are `-static -static-pie -fuse-ld=lld`;
the sysroot preflight therefore also requires glibc's `rcrt1.o`.
The amd64/arm64 cgo and external-link paths retain their existing `-static`
flags and Ubuntu 22.04 release job. A separate Ubuntu 24.04 Loong64 release
job uploads its assets after the primary release is published; Loong64
failure does not hold up amd64/arm64 publication.

Linux E2E additionally needs `go`, `timeout`, `cc`, OpenSSL development
headers, and `tshark` for keylog/pcapng. The full GnuTLS contract also needs
pkg-config and GnuTLS development headers.

Android E2E additionally needs a Linux host with kernel >= 4.18, Go, `timeout`,
`adb`, a modern JDK with `javac` and a `jar` supporting `--create --file`
(JDK 9+), `tshark`, and host dumpcap capture permission.
Set `ANDROID_SDK_ROOT` or `ANDROID_HOME`; install the selected
`platforms/android-<API>/android.jar` and build-tools containing `d8`. The
device/emulator must be rooted/userdebug API 33+ with SELinux not Enforcing.

### Kernel headers for non-CO-RE and cross builds

- A native non-CO-RE build defaults to `/lib/modules/$(uname -r)/build`, with
  `/lib/modules/$(uname -r)/source` when present. Override with
  `KERN_BUILD_PATH` and `KERN_SRC_PATH` when headers live elsewhere.
- A cross build needs an extracted and configured Linux source tree for the
  target architecture. Point `KERN_HEADERS` at that tree; the Makefile runs
  the target architecture's `make prepare` step, but the tree still needs a
  usable `.config` and cross toolchain.
- Merely installing a `linux-source` tarball is insufficient. CI extracts it,
  creates/configures `.config`, and prepares it for the target architecture.

## Build graph, tags, and generated files

```text
kern/*.c
  -> .build/<target>-<goarch>/bytecode/*_kern_{core,noncore}.o
  -> assets/ebpf_probe_<target>_<goarch>_bindata.go
  -> .build/<target>-<goarch>/bin/ecapture
  -> bin/ecapture (compatibility copy used by E2E and direct invocation)
```

- Linux production tags: `linux,netgo,ebpfassets,dynamic`.
- Android production tags: `ecap_android,netgo,ebpfassets,dynamic`.
- `assets/ebpf_probe_stub.go` is selected without `ebpfassets`. It supports a
  clean-checkout compile path but cannot load a real probe asset.
- `dynamic` selects the real elibpcap integration; the build links the
  repository-built libpcap through CGO.
- Do not hand-edit or commit `bytecode/*.o`, `bytecode/*.d`, `.build/`,
  generated `assets/ebpf_probe*.go`, generated LoongArch `vmlinux.h`,
  `bin/ecapture`, `.check*`, or `coverage.out`.
- Generate Protobuf and stringer files from their documented source commands;
  do not patch generated Go manually.

## Canonical build recipes

Use serial, clean-first commands for deterministic validation:

```sh
git submodule update --init --recursive
make clean
make env
make all
test -x bin/ecapture
file bin/ecapture
```

Non-CO-RE build:

```sh
make clean
make nocore
```

CO-RE-only build:

```sh
make clean
make core
```

Cross-compile from x86_64 Linux to arm64 Linux:

```sh
make clean
KERN_HEADERS=/path/to/configured/linux-source \
  CROSS_ARCH=arm64 make env
KERN_HEADERS=/path/to/configured/linux-source \
  CROSS_ARCH=arm64 make all
```

Build an arm64 Android non-CO-RE artifact on Linux:

```sh
make clean
KERN_HEADERS=/path/to/configured/linux-source \
  ANDROID=1 CROSS_ARCH=arm64 make env
KERN_HEADERS=/path/to/configured/linux-source \
  ANDROID=1 CROSS_ARCH=arm64 make nocore
```

An aarch64 Linux host can target x86_64 with `CROSS_ARCH=amd64`. Use only
architectures implemented by `variables.mk`, and match Android artifacts to
the actual device/emulator architecture.

Cross-build Linux/loong64 on Ubuntu 24.04 x86_64. First build a LoongArch
Linux 6.6+ `vmlinux` with BTF from the installed `linux-source` package:

```sh
builder/prepare-loong64-kernel.sh /path/to/linux-source
make clean CROSS_ARCH=loong64
KERN_HEADERS=/path/to/linux-source \
  LOONG64_VMLINUX=/path/to/linux-source/vmlinux \
  CROSS_ARCH=loong64 make env
KERN_HEADERS=/path/to/linux-source \
  LOONG64_VMLINUX=/path/to/linux-source/vmlinux \
  CROSS_ARCH=loong64 make all
```

The generator rejects a pre-6.6 source, a non-LoongArch ELF, or a `vmlinux`
without `.BTF`, then records the kernel version, SHA-256, and bpftool version in
the ignored `kern/bpf/loongarch/vmlinux.source`. Kbuild prepare uses
`ARCH=loongarch LLVM=-18`; CO-RE uses `clang-18 -target bpfel`; non-CO-RE uses
`clang-18 --target=loongarch64-linux-gnu` piped to `llc-18`.

### Build traps

- `make build` is not a Go-only shortcut. Its phony dependencies trigger
  libpcap, core/non-core bytecode, and asset work.
- Architecture-specific libpcap, bytecode, Go intermediates, and generated
  asset filenames live under `.build/` or include the target architecture.
  Still run `make clean` before deterministic release validation and before
  switching `all` versus `nocore` for the same target.
- Prefer serial clean-first builds. `assets`, `assets_core`, and
  `assets_noncore` all write the selected architecture's
  `assets/ebpf_probe_<target>_<goarch>_bindata.go`; do not request those asset targets
  together in one parallel make invocation.
- `.check*` files cache tool checks. Clean after changing the toolchain.
- `make clean` removes the selected target's `.build/` tree and generated
  asset, the compatibility `bin/ecapture`, check stamps, and legacy shared
  bytecode. It does not remove other architecture trees or `coverage.out`.
- Archive and Debian recipes copy from the selected architecture's `.build/`
  binary, not from the shared compatibility path.
- Network/source-generation scripts under `utils/` are not routine build or
  validation steps. Read them before running them.

## Formatting

Format only touched files and inspect the resulting diff. These direct tools
may run on an editing workstation when compatible versions are installed:

```sh
gofmt -w <changed-go-files>
goimports -local github.com/gojue/ecapture/v2 -w <changed-go-files>

ECAPTURE_CLANG_STYLE='{BasedOnStyle: Google, IndentWidth: 4, TabWidth: 4, UseTab: Never, ColumnLimit: 120, AlignAfterOpenBracket: DontAlign, BinPackArguments: true, BreakStringLiterals: false}'
clang-format -i -style="$ECAPTURE_CLANG_STYLE" <changed-c-files>
```

Use the exact `STYLE` value from `variables.mk`. `make format` is a Linux-only,
broad C target that modifies `kern/*.c`, selected headers, and `utils/*.c`; it
does not format Go. Run it only when the full formatting diff is intended.

## Unit tests and lint

All commands in this section run on Linux.

Targeted test example:

```sh
go test ./internal/probe/openssl
```

The default/stub-tag CI unit gate is:

```sh
go test -v -race ./...
```

For production-tag lint and race tests, generate real assets first:

```sh
make clean
make all

CGO_ENABLED=1 \
CGO_CFLAGS="-O2 -g -I$PWD/lib/libpcap" \
CGO_LDFLAGS="-O2 -g -L$PWD/.build/linux-$(go env GOARCH)/libpcap -lpcap" \
golangci-lint run --build-tags=ebpfassets,dynamic ./...

make test-race
```

The lint flags point CGO at the repository-built libpcap; a deliberate local
system-wide installation is an alternative but is not part of the maintained
CI flow. `make test-race` builds libpcap and supplies its own CGO flags, but it
does not generate a
missing architecture-specific `assets/ebpf_probe_<target>_<goarch>_bindata.go`.
Default-tag race tests do not replace
production-tag validation.

Unit tests do not prove that a probe can load, attach, or capture on a real
kernel. Use strict E2E for runtime behavior.

LoongArch has no GitHub-hosted native runner. The Loong64 job in
`.github/workflows/pr_build_debug.yml` cross-builds on hosted Ubuntu 24.04 for
pull requests, validates the artifact and toolchain, and runs QEMU user-mode
CLI and GoTLS instruction smoke tests. There is no separate Loong64 branch-push
workflow or maintained LoongArch E2E job; eBPF load, attach, and capture
behavior remain unverified by CI.

## Maintained Linux E2E

The maintained harness supports Ubuntu 22.04+ on amd64/arm64 and uses
deterministic local TLS workloads.

```sh
make clean
make all

sudo env PATH="$PATH" \
  E2E_MODULES='tls gotls' \
  E2E_MODES='text keylog pcapng' \
  bash test/e2e/run_e2e.sh
```

Single-module entry points include:

```sh
sudo env PATH="$PATH" make e2e-tls
sudo env PATH="$PATH" make e2e-gotls
sudo env PATH="$PATH" make e2e-gnutls
```

`make e2e`, `make e2e-basic`, and `make e2e-advanced` are compatibility
aliases for the same `e2e-linux` matrix; their names do not indicate different
coverage. The default matrix is `tls gotls gnutls` in text, keylog, and pcapng
modes. Each module's text matrix also verifies same-probe HTTP reload output
inheritance, explicit destination replacement, and rejection without losing
the active output.

Public text event destinations for Bash, Zsh, and MySQL have a separate strict
suite. It requires interactive Bash/Zsh and a C++ compiler; the MySQL probe
uses a deterministic local `dispatch_command` fixture rather than a host
database version:

```sh
sudo env PATH="$PATH" bash test/e2e/linux/common_config_test.sh
```

GnuTLS is a strict gating suite alongside OpenSSL and GoTLS. Its versioned
master-secret offsets mean that a passing build against one distribution does
not replace validation against every changed version mapping. Do not weaken
its assertions.

### Success and failure semantics

- Text mode must find the deterministic captured plaintext token.
- Keylog mode must use eCapture-emitted TLS secrets to decrypt an independent
  simultaneous packet capture with `tshark`.
- Pcapng mode must clear external keylog preferences and decrypt eCapture's
  own pcapng using its embedded TLS Decryption Secrets Block.
- Output-pipeline changes must also run the maintained operational-log and
  text/keylog/pcapng cases over file, TCP, binary WebSocket, and stdout. They
  verify operational/event isolation, final flush, valid network pcapng
  reconstruction, and strict typed eCaptureQ `PROCESS_LOG` plus correctly
  classified text/keylog/pcapng `EVENT` delivery with required metadata.
- New multi-connection tests must verify each stream independently. Android
  currently verifies its TLS 1.2 and TLS 1.3 streams separately; do not claim
  every existing Linux case does so.
- Fatal logs, decoder failures, lost samples, buffer overflow, and
  load/attach/start failures are hard failures.
- Successful plaintext previews are limited to 50 characters.
- Failed artifacts are always preserved. Set `E2E_KEEP_ARTIFACTS=1` to keep
  successful artifacts too.

Shared assertions are in `test/e2e/lib/testlib.sh`; Linux-specific setup is in
`test/e2e/linux/common.sh`. Older Bash/database and permissive eCaptureQ
scripts are outside the default maintained TLS matrix; strict typed eCaptureQ
coverage is part of the module suites.

## Android E2E

Build artifacts on a Linux host, selecting the device architecture and using
the configured kernel source described above:

```sh
make clean
KERN_HEADERS=/path/to/configured/linux-source \
  ANDROID=1 CROSS_ARCH=arm64 make nocore
ANDROID_API_LEVEL=33 bash test/e2e/android/build_boringssl_client.sh
```

Then prepare the connected device/emulator and run:

```sh
make setup-android-env
make e2e-android-all
```

The workload build requires `ANDROID_SDK_ROOT` or `ANDROID_HOME`, the selected
API's `android.jar`, a build-tools-compatible modern JDK (`jar` needs its JDK
9+ long-option syntax), and `d8`. Host helpers require Go and `timeout`. The
device/emulator must satisfy the architecture-specific kernel minimum, allow
`adb root`, and not keep SELinux Enforcing. CI covers Android API 33-36 on
x86_64 emulators. The Java workload is intentional because Android
`HttpsURLConnection` exercises Conscrypt/BoringSSL; a Go HTTPS client would
exercise Go's TLS stack instead.

Read `test/e2e/README.md` before running Android tests. Use `ADB_SERIAL` when
more than one device is attached.

## Performance benchmarks

The OpenSSL benchmark has a userspace microbenchmark and a real Linux/root
workload. Run them only on Linux:

```sh
go test -run '^$' -bench '^BenchmarkTLSDataEvent' -benchmem \
  ./internal/probe/openssl

make clean
make all
sudo make benchmark-tls
```

The end-to-end harness defaults to the short-connection 96 KiB upload workload
from issue #990 and writes private raw artifacts below `/tmp/ecapture-benchmark`.
It measures unique request/response marker loss separately from perf lost-sample
logs. See `docs/performance-benchmarks.md` for tunables and result semantics.

## Minimum verification by change

| Change | Minimum evidence |
| --- | --- |
| Documentation only | Check paths, commands, links, and current source facts; no Linux build required |
| Go logic | Touched-file formatting, targeted tests, full `go test -v -race ./...`, and production-tag golangci-lint after generating real assets; report unavailable Linux gates |
| Event decoder/ABI | Byte-level malformed, short, maximum, and padded-sample tests |
| eBPF C or manager setup | Clean CO-RE and non-CO-RE builds for every affected architecture |
| CLI/output/capture mode | Relevant strict E2E mode on a real Linux/Android kernel |
| OpenSSL/BoringSSL mapping | Mapping tests, both asset variants, and real-library validation |
| CI workflow | Least privilege, fork/trusted boundary, and relevant workflow behavior |
| Loong64 build/toolchain | Hosted Ubuntu 24.04 cross-build; LLVM-18 version gate; libpcap `config.log`; LoongArch ELF/archive members; static PIE; LLD evidence; QEMU user smoke |
| Loong64 runtime | No maintained E2E gate; cross-build and QEMU user-mode smoke do not establish eBPF load/attach/capture correctness |

If required infrastructure is unavailable, list the exact commands not run and
why. A static inspection is not a successful Linux build, race test, probe
attachment, or E2E capture.
