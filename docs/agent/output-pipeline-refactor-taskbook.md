# Output pipeline refactor taskbook

Status: implemented; this file records the delivery checklist and verification
contract. The authoritative architecture is `output-pipeline.md`.

## Scope

The refactor separates operational logs from captured events, makes text,
keylog, and pcapng destination-independent, centralizes ByteSink construction,
and replaces the eCaptureQ Writer illusion with typed publishers. Probe/event
ABI and unrelated v2 P0 work remain out of scope.

## Non-negotiable invariants

1. Operational logs and captured events are classified before transport
   selection.
2. Captured payloads and TLS secrets never enter `--logaddr` or eCaptureQ
   `PROCESS_LOG`.
3. Capture mode selects representation; an address selects a destination.
4. Text, keylog, and pcapng encoders do not depend on a file implementation.
5. eCaptureQ receives typed records and is not an `io.Writer` or `ByteSink`.
6. Pcapng packet/DSB ordering, synchronous keylog flush, final drain, and sole
   close ownership remain intact.
7. Shared writers and handlers are concurrency-safe and tolerate repeated
   `Close` calls.
8. Short writes, flush/close failures, queue overflow, and delivery loss are
   observable.
9. Linux/Android production tags, event ABI, and generated-asset rules remain
   unchanged unless this refactor explicitly requires a protocol update.

Unix sockets, probe/event ABI changes, TLS secret derivation, generic hot
reload redesign, and unrelated v2 P0 items remain outside this task.

## Delivered work packages

- O1: explicit `ByteSink`, typed publisher records/contracts, borrowed runtime
  dependencies, and ownership documentation;
- O2: independent text stdout, Keylog over an arbitrary ByteSink, and a
  serialized pcapng session with synchronous DSB flush and shutdown drain;
- O3: one destination factory for stdout, file/file URI, TCP, and binary
  WebSocket, including early incompatible-combination validation;
- O4: uniform TLS-family `EventCollectorAddr`, legacy flag normalization,
  idempotent validation, and reload dependency reattachment;
- O5: one CLI/probe operational logger graph using stderr plus optional
  `--logaddr` and typed eCaptureQ fan-out;
- O6: eCaptureQ `PROCESS_LOG`/`EVENT` publishers, bounded process history,
  observable backpressure, protocol metadata, and joined shutdown;
- O7: unit/integration/race and strict Linux E2E coverage for content,
  transports, isolation, format validity, and exit flushing.

## O1: sink and publisher contracts

The raw transport contract is `writers.ByteSink`: `Write`, `Name`, `Flush`,
and `Close`. `OutputWriter` remains an alias for source compatibility. Typed
destinations implement `domain.OperationalLogSink` or
`domain.CapturedEventSink`; these contracts retain channel, format,
sensitivity, and event metadata.

`output.RuntimeDependencies` carries the process-owned logger and typed event
publishers into a probe. It is excluded from configuration JSON and cloned on
attachment so reload cannot serialize or lose the dependencies. Probes and
handlers borrow typed publishers; the CLI runtime closes them.

Acceptance coverage includes interface assertions, JSON exclusion, error
wrapping, concurrent writes, and idempotent close.

## O2: destination-independent representations

### Text

Text handlers write captured event text directly to an event ByteSink. The
stdout sink is independent from zerolog and preserves existing `String()` /
`StringHex()` formatting without adding operational-log fields.

### Keylog

`KeylogWriter` decorates an arbitrary ByteSink. It appends exactly one newline
without changing caller-owned input, propagates flush/close errors, and owns
the sink. Deduplication remains in `KeylogHandler`. Pcapng mode may construct a
second keylog writer for the legacy standalone artifact.

### Pcapng

`pcapng.Session` is a serialized pcapng representation session over a generic
ByteSink. One goroutine owns `pcapgo.NgWriter`; packet and Decryption Secrets
Block requests are copied before enqueue, ordered, synchronously flushable, and
fully drained at shutdown. `pcapng.KeylogAdapter` is a borrowed view and never
closes the shared session or sink. `PcapngHandler` is the sole session/sink
owner.

Memory, file, TCP, and binary-WebSocket integration tests validate both packet
blocks and DSB blocks. Failure and race tests cover short writes, flushing,
close, concurrent producers, and repeated shutdown.

## O3: centralized destination construction

`writers.WriterFactory` is the only raw destination selector used by the
default text path and TLS-family keylog/pcapng paths:

- empty or `stdout` is valid as the text default;
- explicit `stdout` is valid for keylog/pcapng;
- a plain path or `file://` creates a file sink;
- `tcp://host:port` creates one ordered raw byte stream;
- `ws://` and `wss://` create an ordered binary-frame stream.

Malformed URIs, unknown schemes, missing mandatory destinations, network
rotation, and pcapng rotation fail during validation. Receivers concatenate
WebSocket binary frames in arrival order. A connection failure ends the
artifact; reconnect never resumes in the middle of a pcapng stream. Sensitive
keylog/pcapng files use restrictive permissions and start as new artifacts.

Operational and event sinks are always constructed independently. Console
operational output uses stderr, and simultaneous explicit pcapng/event stdout
and operational stdout is rejected before probe initialization.

## O4: CLI normalization and compatibility

OpenSSL, GoTLS, and GnuTLS use `EventCollectorAddr` as the primary destination
for every capture mode:

- text defaults to stdout;
- keylog requires a destination; `--keylogfile` remains its legacy primary
  file alias;
- pcapng requires a destination; `--pcapfile` remains its legacy primary file
  alias;
- in pcapng mode, `--keylogfile` remains an optional secondary artifact;
- explicitly setting both `--eventaddr` and the applicable primary legacy
  alias is a validation error.

Cobra default filenames retain their previous behavior. Normalization is
idempotent, shared fields are copied by every TLS-family command, HTTP JSON
factories bind the same `BaseConfig` fields, and reload reattaches the runtime
dependencies before repeated validation and probe construction.

## O5: unified operational logging

The CLI constructs one process-lifetime operational logger graph. It fans out
to stderr, an optional file/TCP/WebSocket `--logaddr` sink, and an optional
typed eCaptureQ operational publisher. BaseProbe receives and uses that same
logger. Event handlers have no reference to the operational ByteSink.

Operational sink flush/close errors are returned from `runProbe`; enabling
eCaptureQ is additive and does not disable `--logaddr` or the raw event sink.

## O6: typed eCaptureQ publication

eCaptureQ implements the typed publisher contracts directly:

- heartbeat uses `HEARTBEAT`;
- runtime records use `PROCESS_LOG` for the status area;
- captured envelopes use `EVENT` for the event table.

The captured envelope carries capture format, sensitivity, timestamp, UUID,
PID/process metadata, available network tuple/direction, payload/original
length, stream identity, and sequence. The publisher handler receives the
original domain event; it never parses an encoded text, keylog, or pcapng
stream. Pcapng mode publishes packet rows, not artifact chunks or DSB-only
secret events.

The hub serializes bounded operational history and live publication. New
clients receive at most 128 process records before the live handoff; captured
events are not retained as history. Queue saturation returns an error and
increments a dropped counter. Server shutdown cancels clients, joins owned
goroutines, and is idempotent. Protocol source and generated Go are updated
together, and the example client dispatches on message type.

## O7: strict end-to-end matrix

The maintained Linux harness exercises OpenSSL, GoTLS, and GnuTLS against a
deterministic local TLS fixture. Each suite verifies:

- invalid/conflicting CLI combinations fail before capture;
- text stdout, file, TCP, and binary WebSocket streams contain captured
  plaintext and no lifecycle logs;
- keylog stdout, file, TCP, and binary WebSocket streams contain valid NSS
  records and decrypt an independent capture;
- pcapng file, TCP, binary WebSocket, and redirected stdout streams contain
  valid blocks, DSB material, and decrypt the deterministic token;
- operational stdout, file, TCP, and binary WebSocket output contains
  lifecycle records and no plaintext or secrets;
- the strict protobuf receiver observes both `PROCESS_LOG` and the correctly
  classified text, keylog, or pcapng `EVENT`, including required metadata,
  while raw event output remains enabled;
- graceful process exit flushes the final record and closes receivers.

Success paths remove sensitive artifacts without printing their contents.

## Required verification

Run only on supported Linux/Android environments as described in
`build-test.md`:

```sh
go test ./<targeted packages>
go test -v -race ./...
make clean
make all
CGO_ENABLED=1 CGO_CFLAGS="-O2 -g -I$PWD/lib/libpcap" \
  CGO_LDFLAGS="-O2 -g -L$PWD/lib/libpcap -lpcap" \
  golangci-lint run --build-tags=ebpfassets,dynamic ./...
make test-race
sudo env PATH="$PATH" E2E_MODULES='tls gotls gnutls' \
  E2E_MODES='text keylog pcapng' bash test/e2e/run_e2e.sh
go test -run '^$' -bench '^BenchmarkTLSDataEvent' -benchmem \
  ./internal/probe/openssl
sudo make benchmark-tls
```

Verification is incomplete unless it checks real output content, pcapng block
structure and DSB decryption, TCP/WebSocket bytes, exit-time flush, channel
isolation, and eCaptureQ message classification. Generated eBPF objects,
binaries, captures, keylogs, coverage files, and sensitive fixtures must not be
committed.

## Definition of done

The refactor is complete only when:

- the two semantic channels and three architectural layers are explicit in
  code, tests, and documentation;
- text, keylog, and pcapng route independently to compatible ByteSinks;
- legacy flags, conflict behavior, and repeated validation are tested;
- CLI and probe lifecycle logs reach only the operational graph;
- eCaptureQ simultaneously publishes typed process and event channels without
  replacing raw sinks;
- ownership, final drain, backpressure, and all errors are observable and
  race-free;
- strict Linux content/format/network/eCaptureQ E2E and required production
  gates pass in an eligible environment;
- applicable Android build/E2E gates are run when that environment is
  available, and unavailable checks are reported rather than claimed;
- architecture, CLI, protocol, examples, and E2E documentation match the
  implementation; and
- no generated eBPF objects, binaries, captures, keylogs, coverage, benchmark
  artifacts, or credentials are committed.
