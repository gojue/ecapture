# eCapture probe development guide for coding agents

Read this guide before adding or changing a probe, eBPF event, attachment,
decoder, capture mode, CLI configuration, OpenSSL mapping, or generated
protocol. Repository-wide rules in `../../AGENTS.md` take precedence. Use
`architecture.md` for runtime ownership and `build-test.md` for verification.

## Start from the nearest working design

Before editing, identify:

- the closest probe with the same attachment type: uprobe/uretprobe, kprobe,
  TC, symbol offset, or Go ABI discovery;
- its supported platforms and build tags;
- perf buffer versus ring buffer behavior;
- output modes and handlers it installs;
- CO-RE and non-CO-RE asset selectors;
- required PID, UID, cgroup, library, or version filters.

Probe implementations are historically uneven. Copy the smallest matching
pattern, then verify every contract below instead of assuming another module
is fully correct.

## Add a probe

1. Add a `factory.ProbeType` and keep string/config mappings synchronized.
2. Create `internal/probe/<name>/config.go`; embed `*config.BaseConfig`, add
   module fields, and implement idempotent validation.
3. Add event structs and decoders. Implement decoding, validation, `String`,
   `StringHex`, `Clone`, `Type`, and `UUID` as required by `domain.Event`.
4. Implement the concrete probe around `*base.BaseProbe`, including manager
   setup, attachments, map/decoder associations, readers, and cleanup.
5. Add `register.go` and register the constructor from `init()`.
6. Import the package from the relevant CLI platform file so registration
   actually runs.
7. Add a Cobra command in `cli/cmd/`, bind flags, copy shared config fields,
   and pass the correct factory type.
8. Update `cli/http/` config factories if runtime configuration supports the
   module.
9. Add `kern/<name>_kern.c` or reuse an intentional shared object. Add an
   independent base target to `variables.mk:TARGETS` when it produces assets.
10. Add `ecap_android`/`!ecap_android` guards and target filtering where
    appropriate.
11. Add config, decoder, malformed-input, lifecycle, and mapping unit tests,
    then the smallest strict Linux/Android E2E case.

Keep factory registration in package initialization. The constructor map is
not designed for mutation after concurrent runtime use begins.

## Attachment, map, and constant contract

Treat these pairs as one atomic change:

| Kernel/user target | Go manager or decoder |
| --- | --- |
| C `SEC("...")` | `manager.Probe.Section` |
| C BPF function name | `EbpfFuncName` |
| target symbol or offset | `AttachToFuncName` or `UAddress` |
| target library/binary | `BinaryPath` |
| C map identifier | `manager.Map.Name` and decoder association |
| C global variable | `manager.ConstantEditor` |
| C event record | Go event and `DecodeFromBytes()` |

Changing only one side often compiles but emits no user-space events. A map is
not live until the manager defines it, the correct decoder is registered, and
a tracked reader is started.

When editing filters or constants such as `target_pid`, `target_uid`, or
`less52`, preserve paths for kernels that cannot rewrite `.rodata` globals.

## Kernel/user event ABI

C event structs and Go decoding code form a binary ABI. Update them together.

- Preserve field order, signedness, fixed widths, byte order, arrays, unions,
  and explicit or implicit padding.
- Use fixed-width C/Go fields for data crossing the map boundary.
- Check all lengths and discriminator values before slicing or copying.
- Accept valid trailing perf-sample alignment padding. Select an event variant
  using a safe minimum size plus validated content, not exact length alone.
- Update validation, clone/string methods, UUID/type behavior, and any handler
  interface assertions with the struct.
- Keep `Event.Validate()` idempotent and non-destructive; decoders may validate
  before the dispatcher validates the same event again.
- For reordered events, retain the BPF monotonic timestamp and implement
  `domain.MonoNsEvent` consistently.
- Add byte-level tests for zero, short, malformed, maximum, and padded inputs.

Useful comparisons include `kern/openssl.h` with
`internal/probe/openssl/event.go`, and `kern/gotls_kern.c` with the GoTLS event
decoder.

## Lifecycle checklist

### Initialize

- Assert/validate the concrete configuration.
- Keep `Validate()` idempotent because the CLI may already have called it.
- Call `BaseProbe.Initialize()` to create common logging, output, dispatcher,
  and default handler state.
- Do not leave resources behind when later initialization fails.

### Start

1. Call `BaseProbe.Start()`.
2. Select the asset using platform, BTF/core mode, architecture, and library
   version.
3. Load bytes from the exact go-bindata key.
4. Build probes, maps, constant editors, and manager options.
5. Initialize and start the manager.
6. Resolve maps and associate decoders.
7. Add any mode-specific handlers.
8. Start every tracked reader.

Do not suppress load, attach, map-lookup, or reader-start failures. Runtime
readers currently warn and continue after a lost sample, while strict E2E
treats any lost-sample evidence as a test failure; preserve that distinction.

### Readers and dispatch

- Use BaseProbe's perf/ring-buffer helpers when possible.
- A custom reader must be registered with `TrackReader()` and execute through
  `GoReaderLoop()` or equivalent tracked ownership.
- Dispatcher fan-out is synchronous and unordered; it does not route on
  `Event.Type()`.
- Multiple readers can invoke one handler concurrently. Writers and handlers
  need synchronization and must not depend on handler order.
- A registered handler needs a non-nil writer and a unique
  `handler.Name() + "-" + handler.Writer().Name()` identity.
- Dispatch returns a handler error only if every handler fails; one successful
  handler masks other handler errors from the caller, although they are logged.
- Heavy work in a synchronous handler can increase sample loss. Add bounded,
  explicit async behavior only when ordering and shutdown are defined.
- Reorder queues are per reader/map, not a cross-map global timeline.

### Stop and close

- `BaseProbe.Stop()` currently changes `isRunning` only; it does not close a
  reader.
- Normal successful concrete close paths stop the eBPF manager and
  module-specific closers, then call `BaseProbe.Close()`.
- Base close closes tracked readers, joins their goroutines, closes common
  closers, then closes the dispatcher.
- Release resources safely after full and partial starts. Change this ordering
  only as an explicit lifecycle refactor with concurrency tests.
- Make repeated close safe. Existing common handlers may be reachable from
  more than one closer.

PostgreSQL currently returns early when manager stop fails and can skip Base
close. Treat that as an existing cleanup defect, not a pattern to copy.

## Add OpenSSL or BoringSSL version support

OpenSSL patch releases do not each have a unique C file. The authoritative
mapping is `sslVersionBpfMap` in `internal/probe/openssl/libs.go`, which maps
version ranges to representative ABI/offset-specific objects.

1. Confirm target OpenSSL/BoringSSL identification and the supported range.
2. Verify relevant `SSL`, `SSL_CTX`, `BIO`, and secret offsets against the
   closest supported ABI.
3. Reuse an existing object when layouts and hooks are identical. Add a new
   `kern/openssl_<version>_kern.c` or BoringSSL source only when necessary.
4. If independently compiled, add its base name to `variables.mk:TARGETS`.
5. Extend `sslVersionBpfMap` and any supported-range constants.
6. Add detection/mapping tests and padded-event regressions.
7. Clean-build core and non-core assets and validate against the real library
   on Linux/Android as appropriate.

Scripts under `utils/` can download and inspect upstream source or generate
offset wrappers. Read them before use; they are not routine formatting or
validation commands.

## Change a CLI or configuration field

Trace the full path:

```text
Cobra flag/binding
  -> module config
  -> explicit BaseConfig field copy in RunE
  -> Validate()
  -> manager constants/attachments or handler setup
  -> cli/http runtime config factory
  -> help/API documentation
  -> unit and E2E tests
```

Adding a field only to `BaseConfig` is insufficient because commands copy
shared fields explicitly and not uniformly. Confirm Android/non-Android
command files separately. Preserve the distinction between operational logs
(`--logaddr`) and captured events (`--eventaddr`).

Reload work needs extra care: the current implementation reuses a canceled
context and retains the original factory probe type. Do not describe or test it
as reliable cross-probe hot swap without fixing those lifecycle constraints.

## Change a capture mode or output

Update all affected layers:

- config validation and CLI flags;
- manager programs/maps/constants selected for that mode;
- map-to-decoder associations and reader startup;
- handler installation and supported event interfaces;
- writer creation, concurrency, close, and error propagation;
- output-specific tests and strict E2E assertions.

For TLS modes, keylog output must contain usable secrets. Pcap mode combines a
packet `PcapngHandler` with a `KeylogHandler`/`pcapng.KeylogAdapter` sharing a
`pcapng.Session`. The resulting pcapng must contain packet blocks and an
embedded TLS Decryption Secrets Block that decrypts without an external keylog
preference.

## Generated protocols and code

- Edit `protobuf/proto/v1/ecaptureq.proto`, regenerate using the documented
  tool versions in `protobuf/README.md`, and commit matching
  `protobuf/gen/v1/` output. Never edit generated `*.pb.go` manually.
- Regenerate `cli/http/status_string.go` from `cli/http/resp.go` with the
  documented `go generate`/stringer flow.
- Real eBPF assets come from `kern/` through `bytecode/`; never patch embedded
  object bytes or `assets/ebpf_probe.go` directly.

## No-event troubleshooting order

When a command starts but captures nothing, check in this order:

1. selected core/non-core, architecture, Android, and library-version asset;
2. target binary/library path and PID/UID/cgroup filters;
3. target symbol, offset, section, and BPF function name;
4. manager probe/map definitions and constant editors;
5. map lookup and correct decoder registration;
6. tracked reader startup and reader-loop errors;
7. decoder size/discriminator validation and trailing padding handling;
8. lost samples, handler blocking, and output writer errors.

Do not weaken validation or silently ignore one of these failures to make a
test pass. Follow `build-test.md` for clean builds and the required evidence
for the affected change.
