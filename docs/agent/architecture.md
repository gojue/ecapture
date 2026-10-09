# eCapture architecture guide for coding agents

Read this guide when changing runtime flow, probe ownership, event dispatch,
output behavior, or package boundaries. Repository-wide rules in
`../../AGENTS.md` take precedence.

## Runtime flow

```text
main.go
  -> cli.Start()
  -> cli/cmd.Execute()
  -> Cobra subcommand RunE
  -> module config + runProbe(probeType, config)
  -> config.Validate()
  -> factory.CreateProbe()
  -> Probe.Initialize() / Start()
  -> assets.Asset("bytecode/...") + ebpfmanager
  -> eBPF perf/ring-buffer sample
  -> EventDecoder.Decode()
  -> events.Dispatcher.Dispatch()
  -> text / keylog / pcapng handler
  -> independently constructed ByteSink
  -> optional typed eCaptureQ EVENT publisher
```

`runProbe` also owns signal handling and runtime configuration reload. Probe
packages are imported by the CLI, which triggers each `register.go` `init()`
and installs a constructor in the global factory.

Deleting a seemingly unused probe import can therefore make
`factory.CreateProbe()` fail at runtime. Registration currently discards
duplicate-registration errors. The factory map has no runtime synchronization;
keep registration in package initialization and do not modify it after
concurrent probe use begins.

## CLI and probe matrix

| CLI | Go package | Main eBPF source | Notes |
| --- | --- | --- | --- |
| `tls` | `internal/probe/openssl` | `kern/openssl*_kern.c`, `kern/boringssl*_kern.c` | OpenSSL/BoringSSL; text, keylog, pcapng |
| `gotls` | `internal/probe/gotls` | `kern/gotls_kern.c` | Go symbol/ABI discovery; text, keylog, pcapng |
| `gnutls` | `internal/probe/gnutls` | `kern/gnutls_*_kern.c` | Versioned offsets; text, keylog, pcapng |
| `nspr` (`nss` alias) | `internal/probe/nspr` | `kern/nspr_kern.c` | NSS/NSPR |
| `bash` | `internal/probe/bash` | `kern/bash_kern.c` | Shell command auditing |
| `zsh` | `internal/probe/zsh` | `kern/zsh_kern.c` | Non-Android |
| `mysqld` | `internal/probe/mysql` | `kern/mysqld_kern.c` | MySQL/MariaDB queries; non-Android |
| `postgres` | `internal/probe/postgres` | `kern/postgres_kern.c` | PostgreSQL queries; non-Android |

With `ANDROID=1`, `variables.mk` keeps BoringSSL/OpenSSL, GoTLS, and Bash
targets and excludes zsh, GnuTLS, NSPR, MySQL, and PostgreSQL.

## Repository map

- `main.go`, `cli/main.go`: thin process entry points.
- `cli/cmd/`: Cobra commands, global flags, module config wiring, lifecycle,
  environment checks, and upgrade/reload orchestration.
- `cli/http/`: runtime configuration HTTP API and platform-specific config
  factories.
- `internal/domain/`: central interfaces for configuration, probes, events,
  decoders, handlers, and dispatch.
- `internal/config/`: `BaseConfig` shared by probe configurations.
- `internal/factory/`: global probe constructor registry.
- `internal/probe/base/`: shared logger, writer, dispatcher, readers, optional
  reorder, and shutdown behavior.
- `internal/probe/<name>/`: one module's config, events/decoders, manager
  setup, attachments, map registration, and lifecycle.
- `internal/events/`: validated synchronous fan-out to registered handlers.
- `internal/output/`: borrowed runtime output dependencies and the zerolog edge
  adapter for typed operational publishers.
- `internal/output/writers/`: active stdout/file/TCP/WebSocket ByteSinks plus
  keylog encoding.
- `internal/output/pcapng/`: the serialized pcapng representation session and
  its borrowed keylog adapter.
- `internal/output/encoders/`: standalone abstractions not currently wired
  into the production probe path.
- `kern/`: eBPF C sources and shared headers. `kern/bpf/<arch>/` contains
  tracked headers; do not regenerate them casually.
- `variables.mk`: targets, architectures, build tags, output names, tools.
  `functions.mk`: version checks and the Go link command.
- `bytecode/`: generated core and non-core BPF objects.
- `assets/ebpf_probe.go`: ignored generated go-bindata output.
  `assets/ebpf_probe_stub.go` only supports builds without real assets.
- `pkg/ecaptureq/`: WebSocket/Protobuf event streaming.
- `pkg/event_processor/`: standalone HTTP/1.x and HTTP/2 reconstruction with
  its own event contracts; not imported by the production CLI path.
- `protobuf/proto/`, `protobuf/gen/`: protocol sources and generated Go.
- `test/e2e/`: maintained Linux/Android harnesses plus older compatibility
  scripts.
- `builder/`: release, image, and package build machinery.

## Central contracts

### Configuration and probes

`domain.Configuration` supplies module validation and shared config access.
Validation can occur in the CLI and again during probe initialization, so it
must remain idempotent and avoid irreversible side effects.

`domain.Probe` defines `Initialize`, `Start`, `Stop`, and `Close`. Concrete
probes normally embed `*base.BaseProbe`:

- BaseProbe borrows the process operational logger, owns dispatcher/sink setup, the default text
  handler, readers, optional perf reorder, and shared shutdown.
- Concrete probes own the eBPF manager, attachments, maps/decoders,
  mode-specific handlers, version selection, and module resources.

### Events and decoders

`domain.Event` is the user-space representation of an emitted binary record.
Implementations provide decode/validate, text and hex rendering, clone, type,
and UUID behavior. Clone semantics are historically uneven; do not assume all
existing implementations make a populated deep copy. The dispatcher calls
`Event.Validate()` even when a decoder already validated the record, so event
validation must be idempotent and free of destructive side effects.

`domain.EventDecoder` instances are associated with maps by name or pointer.
`domain.MonoNsEvent` makes an event eligible for perf reorder and must preserve
the BPF monotonic timestamp. Reorder also requires `GetPerfReorder()` to be
enabled and the decoder's prototype event to implement that interface.

## Lifecycle and concurrency

Typical concrete lifecycle:

1. Validate the concrete config and call `BaseProbe.Initialize()`.
2. Call `BaseProbe.Start()`.
3. Select and load the embedded BPF object.
4. Initialize and start the eBPF manager.
5. Resolve event maps and associate their decoders.
6. Start tracked perf/ring-buffer readers.
7. During shutdown, `runProbe` cancels its context, calls `Stop`, then calls
   the concrete `Close` implementation.

`BaseProbe.Stop()` currently changes only `isRunning`; it does not close a
reader. Concrete `Close` implementations normally stop the eBPF manager and
module-specific resources before calling `BaseProbe.Close()`. Base close then
closes its tracked readers, waits for reader loops, and finally asks the
dispatcher to close every registered handler exactly once.

All partial-start cleanup and repeated `Close` paths must be safe. Custom
readers must use both `TrackReader()` and `GoReaderLoop()` or equivalent
tracking so Base close does not race with dispatch.

The dispatcher has important semantics:

- It validates then fans an event out synchronously.
- It invokes only handlers whose explicit `Supports(Event)` returns true.
- Handler map iteration order is undefined.
- Slow handlers block the reader that called dispatch.
- Multiple map readers can enter the same handler concurrently.
- Perf reorder is local to one map/reader, never a global order across maps.
- Byte-backed handler registration uses handler and sink names; typed
  publisher handlers have a nil `Writer()` and a self-contained unique name.
- Dispatch aggregates every supported-handler failure. Successful fan-out
  cannot hide another destination failure, and no supporting handler is an
  explicit error.

Handlers and sinks are concurrency-safe and idempotently closeable. The
dispatcher is the sole handler close owner; typed publishers are borrowed
process-lifetime dependencies.

## Output semantics

- `--logaddr`: operational logs only, fanned out with stderr.
- `--eventaddr`: the primary text/keylog/pcapng ByteSink for TLS, GoTLS, and
  GnuTLS; capture mode selects representation and the address selects transport.
- `--ecaptureq`: additive typed `PROCESS_LOG` and `EVENT` publication.
- `--keylogfile`: legacy primary alias in keylog mode and optional secondary
  keylog artifact in pcapng mode.
- `--pcapfile`: legacy primary pcapng-file alias.

A valid pcapng result contains packet blocks and an embedded TLS Decryption
Secrets Block, not merely a non-empty file. CLI and BaseProbe lifecycle records
use the same operational logger graph. See `output-pipeline.md` for contracts,
ownership, the destination matrix, and eCaptureQ semantics.

## Asset and platform model

```text
kern/<target>_kern.c
  +-> bytecode/<target>_kern_core.o ----+
  +-> bytecode/<target>_kern_noncore.o -+-> assets/ebpf_probe.go
                                             -> bin/ecapture
```

Asset keys, `variables.mk:TARGETS`, and Go selectors must agree exactly. The
real asset file uses the `ebpfassets` tag; the stub lets clean-checkout code
compile but `Asset()` cannot start a probe. The `dynamic` tag selects the real
elibpcap integration.

- Linux production tags: `linux,netgo,ebpfassets,dynamic`.
- Android production tags: `ecap_android,netgo,ebpfassets,dynamic`.
- Android intentionally uses Linux system semantics plus `ecap_android`, not
  an ad-hoc `GOOS=android` workflow.
- Most platform splits use `ecap_android`/`!ecap_android`; inspect nearby
  helpers because some low-level files also use standard `android` tags.

## Current implementation boundaries

- GnuTLS version selection is patch-specific because its master-secret offsets
  vary across releases. Keep `gnuTLSVersionAssets`, the matching C sources,
  and `variables.mk:TARGETS` synchronized.
- Runtime reload uses a fresh probe context and reattaches borrowed runtime
  output dependencies, but keeps the originally selected factory probe type.
- Shared CLI fields are copied manually into module configs, not uniformly.
- Event rotation reaches file-backed text/keylog sinks and is rejected for
  pcapng and network sinks. Truncate size and bytecode-file mode still have no
  current production consumers.
- `--btf=0` is described as auto, while several selectors choose CO-RE only
  when the value is exactly `1`.
- PostgreSQL's current non-core asset spelling is inconsistent with the
  generated `*_kern_noncore.o` convention; do not copy it.
- `pkg/event_processor` and `internal/output/encoders` are not in the live
  production event path. `pkg/event_processor` has a separate event interface
  and EventType ordering, so reconnecting it requires an explicit adapter.

For changes to any of these areas, also read
`probe-development.md` and `build-test.md` in this directory.
