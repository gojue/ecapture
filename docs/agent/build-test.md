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
  >= 5.5.
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
  -> bytecode/*_kern_core.o and *_kern_noncore.o
  -> assets/ebpf_probe.go
  -> bin/ecapture
```

- Linux production tags: `linux,netgo,ebpfassets,dynamic`.
- Android production tags: `ecap_android,netgo,ebpfassets,dynamic`.
- `assets/ebpf_probe_stub.go` is selected without `ebpfassets`. It supports a
  clean-checkout compile path but cannot load a real probe asset.
- `dynamic` selects the real elibpcap integration; the build links the
  repository-built libpcap through CGO.
- Do not hand-edit or commit `bytecode/*.o`, `bytecode/*.d`,
  `assets/ebpf_probe.go`, `bin/ecapture`, `.check*`, or `coverage.out`.
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

### Build traps

- `make build` is not a Go-only shortcut. Its phony dependencies trigger
  libpcap, core/non-core bytecode, and asset work.
- Run `make clean` before switching architecture, `ANDROID`, or `all` versus
  `nocore`. Asset rules consume `bytecode/*.o`, so stale objects can be
  embedded into the wrong binary.
- Prefer serial `make clean && make all`. Parallel `make all -jN` can schedule
  `assets` and `assets_noncore` together; both write
  `assets/ebpf_probe.go`, creating a known race.
- `.check*` files cache tool checks. Clean after changing the toolchain.
- `make clean` removes generated objects/dependencies, embedded assets,
  `bin/ecapture`, check stamps, and libpcap build output; it does not remove
  `coverage.out` or source directories.
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
CGO_LDFLAGS="-O2 -g -L$PWD/lib/libpcap -lpcap" \
golangci-lint run --build-tags=ebpfassets,dynamic ./...

make test-race
```

The lint flags point CGO at the repository-built libpcap; installing its
headers/library system-wide as CI does is an alternative. `make test-race`
builds libpcap and supplies its own CGO flags, but it does not generate a
missing `assets/ebpf_probe.go`. Default-tag race tests do not replace
production-tag validation.

Unit tests do not prove that a probe can load, attach, or capture on a real
kernel. Use strict E2E for runtime behavior.

## Maintained Linux E2E

The maintained harness supports Ubuntu 22.04+ and uses deterministic local
TLS workloads.

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
modes.

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

If required infrastructure is unavailable, list the exact commands not run and
why. A static inspection is not a successful Linux build, race test, probe
attachment, or E2E capture.
