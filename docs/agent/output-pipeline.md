# Output pipeline architecture

Status: implemented target architecture.

## Semantic channels and layers

The output path has three layers and two semantic channels:

```text
OperationalLogRecord -> operational logger ------------------+-> stderr
                                                             +-> --logaddr ByteSink
                                                             +-> eCaptureQ PROCESS_LOG

domain.Event -> EventDispatcher -> TextHandler ----------------+-> event ByteSink
                                -> KeylogHandler --------------+-> event ByteSink
                                -> PcapngHandler/pcapng.Session +-> event ByteSink
                                -> low-latency pcapng -> SDK -> text ByteSink
                                -> typed publisher --------------> eCaptureQ EVENT
```

The layers are:

1. semantic sources: operational records and captured domain events;
2. routing/representation: logger, dispatcher, handlers, and encoders;
3. destinations: independently constructed `ByteSink` instances or typed
   eCaptureQ publishers.

Classification happens before representation and transport selection.
Captured payloads and TLS secrets must never enter `--logaddr` or eCaptureQ
`PROCESS_LOG`. Raw artifacts and typed eCaptureQ events are additive outputs.

## Contracts and ownership

`internal/output/writers.ByteSink` is the raw transport contract:

```go
type ByteSink interface {
    io.Writer
    Name() string
    Flush() error
    Close() error
}
```

`OutputWriter` remains a compatibility alias. Supported sinks are stdout,
file, ordered TCP, and ordered binary WebSocket frames. Callers reconstruct a
WebSocket artifact by concatenating frame payloads in arrival order. A failed
connection terminates the stream; there is no reconnect in the middle of a
pcapng artifact.

`writers.WriterFactory` centralizes raw destination construction for the
default text path and TLS keylog/pcapng paths. Text handlers preserve event
`String()` / `StringHex()` output without operational-log fields.
`KeylogWriter` normalizes each record to one trailing newline without
modifying caller-owned bytes, reports short writes, and forwards flush/close
errors. `KeylogHandler` owns keylog deduplication.

The dispatcher owns registered handlers. A handler owns its encoder/session
and the primary ByteSink it was constructed with. `pcapng.KeylogAdapter` is a
borrowed DSB view: it may synchronously flush queued keylogs but never closes
the `pcapng.Session` or sink. The session copies packet and keylog bytes before
queueing them; its serving goroutine serializes encoder writes.
`PcapngHandler` stops producers, drains DSBs and packets, flushes the pcapng
encoder and sink, then closes the sink. Close is
idempotent and failures from every layer are joined and returned.

Typed destinations implement `OperationalLogSink` or `CapturedEventSink`.
eCaptureQ implements both contracts and is deliberately not an `io.Writer` or
ByteSink. The zerolog adapter exists only at the operational-logger edge.
Injected runtime dependencies are borrowed, excluded from configuration JSON,
and reattached after reload. Serializable captured-event destination and
rotation settings remain in the probe configuration: omitted HTTP reload
fields inherit from the active generation, while explicit empty/zero values
are preserved.

## Mode, text source, and destination matrix

`tls`, `gotls`, and `gnutls` default to the `pcapng` source in text mode. When
`--ifname`/`-i` is omitted for packet capture, the shared
`config.CaptureInterfaceConfig` selects an up, non-loopback Ethernet interface from the main-table IPv4/IPv6 default route with the lowest metric.
Without a usable default route it prefers the largest historical RX+TX byte
counter, then an up interface; ties use the lowest interface index. This is
a startup heuristic, not traffic sampling or policy-routing resolution. A
WARN startup log identifies the interface and reason and tells users how to
override it with `-i`/`--ifname`. Explicit choices (including `lo`) are retained,
and repeated validation keeps the selected interface. No usable candidate
produces an actionable configuration error. Explicit `--text-source=hook` retains
function-hook capture without an interface. All three HTTP configs use the same
mode-dependent default when `text_source` is omitted or empty; keylog/pcapng modes do not inherit it.

| Mode / text source | Representation | Valid primary ByteSink | eCaptureQ event |
| --- | --- | --- | --- |
| text (hook) | UTF-8 event text | empty/stdout, file, TCP, binary WebSocket | structured ordinary event |
| text (pcapng source) | Application messages, streaming events or raw TLS/QUIC/DTLS data | empty/stdout, file, TCP, binary WebSocket | sensitive reconstructed event with text format |
| keylog | NSS Key Log lines | explicit stdout, file, TCP, binary WebSocket | structured sensitive event |
| pcapng | ordered pcapng with DSB | explicit stdout, file, TCP, binary WebSocket | sensitive packet rows, never raw pcapng chunks |

`-m text --text-source=pcapng` uses the same packet and keylog dispatcher records as pcapng, but
passes their pcapng encoding through a pipe to `ecapture_decryptor`. The SDK
reads DSB blocks incrementally, waits for late secrets, reassembles TCP and
HTTP, then emits complete messages or the explicitly selected events. The pcapng session flushes
at a short interval without a fixed DSB grace period. The plaintext sink is
the primary destination; a pcapng copy and standalone keylog are optional.
The SDK callback publishes the reconstructed message to eCaptureQ directly;
the raw packet publisher is not registered for this text source.

### Decryption termination and diagnostics

The streaming API returning while capture is active is a terminal pipeline event,
including an unexpected nil/EOF return. A returned API cannot consume further
input, even when its error contains old connection failures. `decrypt.Sink`
latches the first cause as `internal/errors.PipelineError`, interrupts both pipe
ends and network output, and calls `BaseProbe.Fail`. The probe's cancellable
context wakes `runProbe` without another packet or keylog event. Dispatch checks
that terminal state before delivery; readers and dispatcher do not log it again.
The CLI logs one safe operational error, cancels the generation, stops the probe,
closes/joins readers and handlers, and exits nonzero. There is no automatic
restart. The full cause remains available through `errors.Is` / `errors.As`;
arbitrary SDK error strings (which can contain captured data) are not logged.
The typed keylog resource-limit sentinel has a specific safe reason.

A pcapng encoder/write/flush failure stops the serving loop at its first error,
rejects new producers, and drops queued data instead of retrying a broken stream.
Packet, DSB and timer failures use the same terminal path for decrypted output.
The session stores one error, rather than repeatedly joining the SDK's historical
connection error list. Cleanup errors are retained in bounded owner-level joins.

Connection diagnostics delivered through `OnDiagnostic` do not signal pipeline
failure. The SDK remains responsible for bounded late-key waiting, record-state
recovery, and isolating an unrecoverable connection or direction. eCapture never
skips an arbitrary TLS record and resumes damaged cipher state. Diagnostics use
one fixed bucket per pipeline (at most one record per five seconds, with a
suppressed count on the next record); there is no per-connection counter map.
Only bounded SDK reason codes are logged, without keys, payloads or connection
identifiers. Ordinary progress diagnostics retain their debug severity.

Normal shutdown drains accepted pcapng data before closing the pipe input; only
an EOF initiated by that close is expected. Cancellation starts a five-second
drain deadline. Expiry cancels the SDK and interrupts pipe and network I/O
without taking the write mutex. A stalled drain is an error, not successful
cleanup. This relies on the SDK joining its workers after input/context
cancellation and typed publishers honoring context. It cannot bound an OS-level
uninterruptible regular-file write/fsync or an arbitrary non-cancellable writer.

Pinned SDK v1.4.3 contract caveat: `api.go:processPcapngStreamMode` joins
`connectionError()` into its result during teardown, and
`pcapng_stream.go:DecryptPcapngStreamWithOptions` joins engine, callback and
context errors without an overall typed outcome. Thus a locally initiated EOF
with historical connection failures can still produce nonzero exit. Do not infer
success from `errors.Is` matching one member of that aggregate. A future SDK
contract must separately identify successful requested completion with bounded
connection diagnostics and fatal input/DSB/callback/worker termination; it must
keep healthy connections processing while connection-local failures are isolated.
No dependency, key-cache capacity, resource limit or SDK recovery policy is
changed here.

TC reports send-context PID/Comm in the event header without modifying wire
packets. `PacketEvent` passes these fields and endpoint provenance to
`Session.WritePacketWithProcess`, which appends an Ethernet trailer in both
file and low-latency sessions: big-endian magic `0xCC0C4CFC`, uint32 PID,
uint8 Comm length, up to 16 Comm bytes, version `1`, endpoint `1` (source) or
`2` (destination), and four zero FCS placeholder bytes. The legacy prefix stays
compatible with `utils/ecapture.lua`; this is packet data, not an EPB option.

Send-context probes also read `current->mm->arg_start/arg_end` through an eBPF
helper, preserving NUL-separated argv bytes up to 256 bytes. Longer argv is
explicitly marked truncated; failed reads stay unknown. No procfs lookup is
performed. Large SKBs omit optional argv to leave room in the perf sample.
`network_map` carries the snapshot alongside PID/Comm. The perf ABI
is a 48-byte header (the original 40-byte prefix plus uint32 argv length and
uint32 truncation flag), then argv bytes and the unchanged packet bytes.
Both file and low-latency sessions write argv in a standard EPB comment:
`eCapture argv v1 <0|1> <base64>`, where the flag denotes truncation. The legacy
PID/Comm trailer is unchanged, so SDK v1.4.1 and older Lua readers retain their
existing behavior; the updated Lua plugin displays quoted argv and truncation.
Arguments are captured data and must not be copied into operational logs.

Decryptor v1.4.2 and later read these EPB comments into optional `ProcessArgs` snapshots.
The reconstructed publisher forwards raw argv and its truncation flag through
additive eCaptureQ fields 18/19 without altering the HTTP payload or connection
identity. Older readers ignore these fields; older senders leave them absent.
Consumers must preserve the raw bytes and truncation flag; process arguments
are captured snapshots, not guaranteed original exec commands.

The matching SDK reads legacy and extended trailers. Ownership is independent
of connection keys: one known local endpoint owns both directions; two local
endpoints use their respective senders. Missing/conflicting ownership stays
unknown, and late observations only affect subsequent callbacks. TC attribution
does not resolve VLAN/IPv6 extension headers, namespace collisions, shared
sockets or missed TCP SYN reuse. Keep the SDK dependency pinned to a version
that reads this trailer, and retain the gopacket replacement.

When the SDK provides `Metadata["tls"]` as a string map, the text/pcapng
publisher copies this non-secret handshake snapshot into eCaptureQ `Event.tls`
(field 20). This does not change the primary text ByteSink representation or
HTTP payload. Version/cipher/ALPN are observed selections, while JA3/JA4 and
SNI come from the first wire ClientHello (Outer for ECH). Missing observations
remain absent. SDK v1.4.3 provides this optional metadata and is the pinned
dependency for handshake output.

`config.DecryptConfig` holds the shared serializable parsing options for TLS,
GoTLS and GnuTLS. `--text-protocol` selects DoT/DoH/DoQ/MQTT/Redis;
`--text-http-events` selects incremental HTTP/SSE/H2 gRPC and permits the
optional `--text-max-decoded-body` gzip expansion bound. `--text-tls-upgrade`
selects one explicit STARTTLS/CONNECT negotiation. `--text-udp-protocol=dtls`
selects the SDK's limited DTLS 1.2 record decoder; UDP otherwise remains QUIC.
All require text/pcapng source. SDK option validation runs before opening sinks.

`--text-raw` selects authenticated TLS bytes, QUIC STREAM chunks and DATAGRAM
messages without application parsing. Tagged events and nested TLS output
preserve all SDK metadata as JSON and payload as lossless hex, including empty
headers/trailers/datagrams. Only actual stream metadata adds offset/end/stream
fields. Text sinks and typed EVENT payloads use the same representation; its
header records the decoded byte length. Untagged complete HTTP messages keep
their existing text representation.
For structured events, typed `OriginalLength` is the length of that text representation. A TLS end
marker denotes the end of captured input, not a complete application message;
QUIC end denotes STREAM FIN. Early-data acceptance and `tls_depth` must not be
dropped or treated as a single application stream. ECH still lacks probe-side
ECH_SECRET/ECH_CONFIG capture; do not infer live support from SDK tests alone.
DTLS master-secret events use version 0xFEFD and the TLS 1.2 CLIENT_RANDOM
keylog representation. Application routing remains explicit. Normal key-update,
HRR and early-data acceptance/rejection progress is logged at debug level;
failure diagnostics remain warnings, subject to the bounded diagnostic bucket
described above. Observers write safe reason codes to the operational logger.

The maintained strict Linux E2E suites exercise operational logs and the
text, keylog, and pcapng representations against all four ByteSink types for
OpenSSL, GoTLS, and GnuTLS. The pcapng text source has a strict live-output file case
with optional pcapng for each module. Typed eCaptureQ receivers cover text,
keylog, pcapng, and the decrypted HTTP path in the OpenSSL suite.

Plain paths and `file://` are files. Unknown or malformed URI schemes fail
validation. Rotation is valid only for file-backed text/keylog streams and is
rejected for pcapng or network sinks. New keylog, pcapng, and reconstructed
plaintext files are created with sensitive permissions. Keylog and pcapng
files are truncated at capture start.

Operational console output uses stderr. Pcapng stdout therefore contains only
binary pcapng. An explicit `--logaddr stdout` plus pcapng `--eventaddr stdout`
is rejected before probe initialization.

## CLI normalization

`--eventaddr` is the uniform primary event destination for OpenSSL, GoTLS, and
GnuTLS. Mode selects representation; address selects transport.

- text defaults to event stdout;
- keylog requires a destination; `--keylogfile` is its legacy primary-file
  alias;
- pcapng requires a destination; `--pcapfile` is its legacy primary-file
  alias;
- in pcapng mode, `--keylogfile` is a separate optional keylog artifact;
- text with `--text-source=pcapng` defaults to plaintext stdout; `--pcapfile` and `--keylogfile` are
  optional artifacts and their Cobra defaults are cleared unless explicitly
  set;
- explicitly setting `--eventaddr` and the corresponding legacy primary flag
  is an error.

Default legacy filenames supplied by current Cobra flags remain compatible.
Calling `Configuration.Validate()` repeatedly preserves the normalized result.

## eCaptureQ protocol

Every WebSocket message is one binary protobuf `LogEntry`:

- `HEARTBEAT` is transport health;
- `PROCESS_LOG` is an operational record for the status area;
- `EVENT` is a captured event for the event table.

`EVENT` includes format, sensitivity, timestamp, UUID, PID/process, available
network tuple and direction, payload/original length, and optional stream
identity/sequence. Publishers consume the original domain event and metadata;
they do not reverse-parse text, keylog, or pcapng bytes. Pcapng DSB-only secret
events are not published as table rows.

Reconstructed events forward the SDK's PID/process fields when available,
using the existing envelope and protobuf fields. Unknown attribution is PID
zero; older SDKs may also supply the placeholder name `decryptor`, which must
not be presented as a captured process. Ordinary publishers accept both
`GetPid() uint32` and
`GetPID() uint64` event accessors, including MySQL query events. UUID remains
module-defined and must not be parsed as a universal process identity.

Connected clients receive live records immediately. A new client first gets
at most the latest 128 operational records, followed by live traffic through a
serialized handoff. Captured events are not retained in startup history.
Queue saturation returns an error and increments the observable dropped count.
Server close cancels the hub, unblocks clients, joins owned goroutines, and is
idempotent.

## Verification contract

Changes must preserve content and failure behavior, not merely create output:

- Unit and race coverage checks short writes, flush/close errors, concurrent
  producers, repeated close, pcapng packet/DSB drain, and queue saturation.
- Runtime dependencies stay out of configuration JSON and remain borrowed
  across reload; repeated validation and legacy flag conflicts are tested.
- Strict TLS E2E checks all supported ByteSinks, independent keylog/DSB
  decryption, operational/event isolation, typed eCaptureQ classification
  alongside raw output, and final delivery during graceful shutdown.

Use [build and verification](build-test.md) for commands and platform gates,
and the [E2E guide](../../test/e2e/README.md) for the maintained matrix. Retain
the performance checks in [performance benchmarks](../performance-benchmarks.md)
when changing hot-path decode, dispatch, or output work.
