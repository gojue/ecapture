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
                                -> low-latency pcapng -> SDK -> HTTP ByteSink
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

The dispatcher owns registered handlers. A handler owns its encoder/session
and the primary ByteSink it was constructed with. `pcapng.KeylogAdapter` is a
borrowed DSB view: it may synchronously flush queued keylogs but never closes
the `pcapng.Session` or sink. `PcapngHandler` stops producers, drains DSBs and
packets, flushes the pcapng encoder and sink, then closes the sink. Close is
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

| Mode / text source | Representation | Valid primary ByteSink | eCaptureQ event |
| --- | --- | --- | --- |
| text (hook) | UTF-8 event text | empty/stdout, file, TCP, binary WebSocket | structured ordinary event |
| text (pcapng source) | complete HTTP/1.1 or HTTP/2 messages | empty/stdout, file, TCP, binary WebSocket | sensitive reconstructed message with text format |
| keylog | NSS Key Log lines | explicit stdout, file, TCP, binary WebSocket | structured sensitive event |
| pcapng | ordered pcapng with DSB | explicit stdout, file, TCP, binary WebSocket | sensitive packet rows, never raw pcapng chunks |

`-m text --text-source=pcapng` uses the same packet and keylog dispatcher records as pcapng, but
passes their pcapng encoding through a pipe to `ecapture_decryptor`. The SDK
reads DSB blocks incrementally, waits for late secrets, reassembles TCP and
HTTP, then emits one request/response at a time. The pcapng session flushes
at a short interval without a fixed DSB grace period. The plaintext sink is
the primary destination; a pcapng copy and standalone keylog are optional.
The SDK callback publishes the reconstructed message to eCaptureQ directly;
the raw packet publisher is not registered for this text source.

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

Connected clients receive live records immediately. A new client first gets
at most the latest 128 operational records, followed by live traffic through a
serialized handoff. Captured events are not retained in startup history.
Queue saturation returns an error and increments the observable dropped count.
Server close cancels the hub, unblocks clients, joins owned goroutines, and is
idempotent.
