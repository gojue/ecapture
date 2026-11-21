# Output pipeline architecture

Status: implemented target architecture.

## Semantic channels and layers

The output path has three layers and two semantic channels:

```text
OperationalLogRecord -----------------------------+-> output terminals/JSON
                                                  +-> stream PROCESS_LOG
core text: packets -> pcapng -> SDK -> TextEvent ---+-> output terminals/JSON
                                                  +-> stream TEXT
native: keylog/pcapng encoder -> native artifact ---+-> output terminal summary
                                                  +-> network native EVENT
pcapng packets/secrets -> subscriber encoder ------+-> stream PCAPNG
```

Classification happens before encoding: runtime logs are `PROCESS_LOG`,
captured data is `EVENT`. Both use the same v2 envelope in JSON and Protobuf.
Native artifacts remain separate files; file `--output` targets receive only
runtime logs in keylog/pcapng mode. Text-source pcapng remains TEXT and does not
publish its optional raw artifacts as native network events.

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

`OutputWriter` remains an internal compatibility alias. The CLI output set
owns terminal/JSON publishers and the stream server. Handlers borrow them.
`JSONPublisher` writes and flushes one v2 `LogEntry` per line, with ordered,
bounded network I/O and latched errors; it never reconnects within a generation.
`ConsolePublisher` serializes whole records and labels every physical line.

`WriterFactory` constructs local native files and JSON destinations. Hook
text retains `String()`/`StringHex()` output; SDK text retains formatted decoded
content plus structured metadata. `KeylogWriter` normalizes each NSS record to
one trailing newline; `KeylogHandler` deduplicates it. `NativeSink` publishes
encoded NSS/pcapng bytes after the encoder, never raw packet rows or summaries.

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
and reattached after reload. Destinations cannot be changed through HTTP, and
core factories reject old destination/rotation fields, including null/zero.
Network outputs close after final drain at each generation boundary. Native
local files append new NSS lines or independent pcapng sections on reload and
rollback, preserving preceding capture data.

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

| Mode / text source | Terminal | Output file | Network JSON / Protobuf v2 |
| --- | --- | --- | --- |
| text (hook) | labelled formatted text | logs + TEXT | logs + TEXT |
| text (pcapng source) | labelled SDK-decoded text | logs + TEXT | logs + TEXT |
| keylog | logs + labelled NSS records | logs only | logs + encoded NSS bytes |
| pcapng | logs + encoded-byte summaries | logs only | logs + encoded pcapng bytes |

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

SDK completion-contract caveat (identified in v1.4.3):
`api.go:processPcapngStreamMode` joins `connectionError()` into its result
during teardown, and
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
v2 `TextEvent.process_args` and `process_args_truncated` (fields 18/19)
without altering the formatted TEXT payload or connection identity. These fields
are nested under `LogEntry.event_payload.text`; v1 decoders are not supported.
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
publisher copies this non-secret handshake snapshot into v2 `TextEvent.tls`
(field 20), nested under `LogEntry.event_payload.text`. This does not change the
formatted TEXT payload. Version/cipher/ALPN are observed selections, while
JA3/JA4 and SNI come from the first wire ClientHello (Outer for ECH). Missing observations
remain absent. SDK v1.4.3 introduced this optional metadata; the current
dependency in `go.mod` is v1.4.4.

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
fields. Terminal events and v2 TEXT payloads use the same formatted
representation; its header records the decoded byte length. Untagged complete HTTP messages keep
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

The maintained strict Linux E2E suites exercise TLS/OpenSSL, GoTLS and GnuTLS
using stdout/stderr, JSON files, outgoing TCP and v2 subscriptions. Tests retain
plaintext/metadata assertions, independent keylog and DSB decryption, native
file isolation, and removal/reload validation.

## CLI normalization

`--output` accepts repeated stdout/stderr, file paths/file://, and outgoing
TCP destinations. Outgoing WS/WSS is unsupported. No explicit output
means stdout; explicit values replace that default. Duplicate targets and
file aliases shared with native artifacts are rejected before opening sinks.
Terminal streams cannot be native artifact destinations.

`--model keylog` requires `--keylogfile`; `--model pcapng` requires `--pcapfile`.
Text-source pcapng may additionally save either artifact. Native files are
created with 0600 permissions, truncated on first capture startup, and appended
on reload/rollback. JSON files append with 0600 permissions. Existing file
permissions are retained. Rotation CLI flags and old output/listener names
are removed, with no compatibility routing.

## Streaming protocol

`--stream-listen ws://host:port/path` exposes only the selected WebSocket path.
Clients must negotiate `ecapture.v2`. Each binary frame is a v2 `LogEntry`:
`HEARTBEAT`, `PROCESS_LOG` or `EVENT`. Event contains a capture-format enum and
matching oneof: TextEvent metadata/payload, KeylogEvent.data, or PcapngEvent.data.
See `protobuf/proto/v2/ecaptureq.proto` and `protobuf/v2` for schema/validation.

A receiver concatenates native bytes in arrival order within one connection.
Message boundaries need not coincide with pcapng block/packet boundaries.
Each late pcapng subscriber gets an independent encoder starting with SHB/IDB,
then future packets and secrets. Historical traffic/secrets are not replayed;
old TLS sessions may not decrypt, and subscriber files differ from local files.
A new client gets the current collector-info snapshot and at most 128 recent
operational logs, never historical events. `collector_info` is a bounded JSON
`PROCESS_LOG` retained separately from log rotation; see `protobuf/PROTOCOLS.md`.

Normal generation shutdown drains encoders/queues and closes WS with code 1000;
failed capture uses 1011. TCP EOF does not prove completeness. Receiver examples
preserve incomplete/abrupt files as partial and start a fresh artifact on a new
connection. A slow subscriber is disconnected; queue/client counts and network
waits are bounded. Server close joins its goroutines and is idempotent.

## Verification contract

Changes must preserve content and failure behavior, not merely create output:

- Unit and race coverage checks short writes, flush/close errors, concurrent
  producers, repeated close, pcapng packet/DSB drain, and queue saturation.
- Runtime dependencies stay out of configuration JSON and remain borrowed
  across reload; repeated validation and removed-flag rejection are tested.
- Strict core TLS E2E checks all supported destinations, independent keylog/DSB
  decryption, operational/event isolation, typed eCaptureQ classification
  alongside JSON/terminal output, and final delivery during graceful shutdown.

Use [build and verification](build-test.md) for commands and platform gates,
and the [E2E guide](../../test/e2e/README.md) for the maintained matrix. Retain
the performance checks in [performance benchmarks](../performance-benchmarks.md)
when changing hot-path decode, dispatch, or output work.
