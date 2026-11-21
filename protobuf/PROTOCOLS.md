# eCapture Protobuf v2 and JSON Lines

[中文](PROTOCOLS-zh_Hans.md) · [Generation](README.md)

The authoritative schema is [proto/v2/ecaptureq.proto](proto/v2/ecaptureq.proto),
namespace `ecapture.v2`, Go import
`pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"`. Runtime v1 output is removed.
This is a breaking wire change: update the decoder, event dispatch, and native
file handling together; do not decode v2 with v1 generated types.

## Transports and framing

- `--stream-listen ws://HOST:PORT/PATH` listens for clients. The handshake must
  offer and negotiate `Sec-WebSocket-Protocol: ecapture.v2`. Each binary
  WebSocket message contains exactly one serialized `LogEntry`.
  Non-browser clients must also supply a valid `Origin` header, as the example does.
- `--output tcp://HOST:PORT` actively connects to the receiver. Each newline
  terminates one ProtoJSON `LogEntry`; buffer across TCP reads.
- `--output FILE` and `--output file:///PATH` use the same JSON Lines encoding.
  In `text` mode they contain operational logs and events. In `keylog`/`pcapng`
  mode these files contain operational logs only; native files are selected
  separately with `--keylogfile`/`--pcapfile`.
- `--output stdout` or `stderr` renders readable lines labeled with `log_type`
  and `module`. It is a terminal representation, not JSON or native file bytes.

ProtoJSON uses the schema's snake_case field names and enum names. Byte fields
are base64; 64-bit integers are JSON strings. Decode bytes exactly once with a
Protobuf JSON implementation and preserve integer precision. Default-valued
fields may be omitted. A terminal prefix is not part of any native artifact.

## LogEntry and validation

| Field | Number | Meaning |
| --- | --- | --- |
| `log_type` | 1 | `HEARTBEAT=0`, `PROCESS_LOG=1`, `EVENT=2`, prefixed `LOG_TYPE_` |
| `event_payload` | 2 | Event member of `oneof payload` |
| `heartbeat_payload` | 3 | Heartbeat member of `oneof payload` |
| `run_log` | 4 | Operational string member of `oneof payload` |
| `module` | 5 | Canonical producer such as `tls`, `gotls`, `gnutls`; empty when unknown |

Dispatch by `log_type` and require its matching `oneof` member. Reject missing
bodies, mismatched discriminators and unknown formats; never guess from a
payload. Module names are open-ended, so preserve unfamiliar names. The
[validation helper](v2/validate.go) implements this contract in Go. Operational
logs, heartbeat records and captured data must not be mixed in native files.

`Heartbeat` contains Unix-seconds `timestamp=1`, `count=2`, and `message=3`.
The listener sends one immediately and every 15 seconds. Count starts at zero
per connection and does not count captured events. New clients receive at most
128 recent operational logs plus the current collector-info record. Captured events, packets and secrets are not
replayed. Queues are bounded; a slow client can be disconnected. This protocol
has no durable acknowledgement, history cursor, or resume capability.

Collector information is a structured `PROCESS_LOG.run_log` JSON object with
`event="collector_info"`, `schemaVersion=1`, and a `collector` object. Optional
fields are `host`, `module`, `mode`, `textSource`, `argv`, `argvTruncated`,
`version`, `buildTime` (RFC3339 UTC), `decryptorVersion`, `commit`, `configListen`,
`streamListen`, `outputs`, and `outputsTruncated`. `argv` records the collector's
startup arguments, not captured process arguments; never execute it. Missing
build facts stay absent. The latest generation replaces the retained snapshot,
which precedes log replay and events after the initial heartbeat. The JSON is
bounded to 256 KiB; argv has at most 256 entries/8192 UTF-8 bytes, outputs 64/8192,
with truncation flags. This uses the existing v2 envelope without a schema change.

## Event content

`Event.capture_format=1` must match exactly one content member:

| CaptureFormat | Value | Oneof member | Meaning |
| --- | --- | --- | --- |
| `CAPTURE_FORMAT_UNSPECIFIED` | 0 | None | Invalid for published events |
| `CAPTURE_FORMAT_TEXT` | 1 | `text=2` | Text payload and capture metadata |
| `CAPTURE_FORMAT_KEYLOG` | 2 | `keylog=3` | `KeylogEvent.data=1`: native NSS Key Log bytes |
| `CAPTURE_FORMAT_PCAPNG` | 3 | `pcapng=4` | `PcapngEvent.data=1`: native pcapng byte stream |

TEXT remains TEXT when reconstructed by `--model text --text-source pcapng`.
KEYLOG bytes come after secret derivation, NSS formatting and deduplication;
they are not human-readable event summaries. PCAPNG bytes include the encoder's
Section Header, Interface Description, Enhanced Packet and Decryption Secrets
Blocks, including packet comments. They are not standalone packet payloads.

Concatenate native `data` in arrival order for one connection and format. A
message may split a keylog line or pcapng block. Do not prepend lengths, labels,
JSON or Protobuf bytes to the saved file, and do not base64-encode again.
Native events intentionally do not invent TextEvent process/network metadata;
extract available packet metadata from pcapng comments after decoding blocks.
Native capture data and text argv/payloads can contain secrets.

## TextEvent

| Number | Field | Type | Semantics |
| --- | --- | --- | --- |
| 1 | `timestamp` | int64 | Unix seconds |
| 2 | `uuid` | string | Producer correlation identifier; not a globally unique message ID |
| 3–6 | `src_ip`, `src_port`, `dst_ip`, `dst_port` | string/uint32 | Available endpoint tuple |
| 7–8 | `pid`, `pname` | int64/string | Available kernel process identity |
| 9 | `type` | uint32 | Internal domain category: 0 Output, 1 ModuleData, 2 Processor |
| 10 | `length` | uint32 | Exact byte length of `payload` |
| 11 | `payload` | bytes | Captured text/decoded representation; may be binary or empty |
| 12 | reserved | — | Former capture-format slot, not reused |
| 13 | `sensitivity` | enum | `SENSITIVITY_NORMAL=0`, `SENSITIVITY_SENSITIVE=1` |
| 14 | `direction` | string | Producer direction when known |
| 15 | `original_length` | uint32 | Original capture/SDK byte length before text formatting, or payload-length fallback |
| 16 | `stream_id` | string | Optional stream identity |
| 17 | `sequence` | uint64 | Producer-local sequence; not a global ordering guarantee |
| 18 | `process_args` | bytes | Optional capture-time NUL-separated argv, up to 256 bytes |
| 19 | `process_args_truncated` | bool | Snapshot hit capture limit and may end mid-argument |
| 20 | `tls` | map<string,string> | Optional non-secret handshake observations |

Do not drop metadata-only events with empty payloads. Preserve bytes and all
metadata when forwarding, including direction, original length, stream ID,
sequence, sensitivity, argv and TLS. The type is not an HTTP request/response
enum. Empty or zero metadata means unavailable; UUIDs may repeat and sequences
may reset after reload. Reconstructed HTTP is TEXT with sensitive classification.
Text prefixes or hex rendering can make `length` larger than `original_length`;
the latter is not a limit on the formatted payload. Only `length == len(payload)`
is required; do not overwrite original capture lengths to match presentation.

Argv can be non-UTF-8 and rewritten by the process; it is not an exact exec
command guarantee. Complete snapshots end in NUL; truncated snapshots contain
256 bytes. Arguments never belong in operational logs.

TLS keys include `version`, `cipher_suite`, `cipher_suite_id`, `server_name`,
`offered_alpn`, `alpn`, `key_exchange_group`, `signature_algorithm`, `ja3`,
`ja3_raw`, `ja4`, and `client_hello` (`initial_wire` / `initial_outer`). Missing
observations remain unknown. Fingerprints use the first wire ClientHello;
negotiated values come from server handshake observations. This map includes
no TLS secrets or certificate-validation guarantee.

## Sessions, reload and file completion

One connection belongs to one capture generation. Reload drains the old
generation, closes its TCP/WS connections, and creates fresh connections on
reconnection. Start a different native file for each connection. Do not append
reconnected keylog/pcapng data to a previous file.

A late pcapng subscriber receives a new encoder/session with fresh section and
interface headers and future packets/secrets only. Historic keys and handshake
packets are not replayed; existing TLS connections may be undecryptable in this
fragment. There is no claim that a late subscription equals the full local file.

A successful WS generation drains the encoder and queues before Close 1000.
Failure uses Close 1011 or disconnect. Save native bytes to `.partial` until a
verified Close 1000 and successful local flush/close/format validation. An EOF,
timeout, killed receiver, malformed record or Close 1006 does not establish
completion. TCP has no application completion marker: EOF alone does not prove
success, even at a block boundary. Retain `.partial` unless an external trusted
completion signal confirms the producer succeeded. Framing checks do not prove
lossless capture or successful TLS decryption.

The [Go receiver](../examples/ecaptureq_client/README.md) demonstrates binary v2
validation, metadata-preserving text display, and safe native artifact saving.
See [output behavior](../docs/event-forward-api.md) and
[HTTP reload](../docs/remote-config-update-api.md) for startup and generation rules.
