# eCaptureQ wire protocol

[中文](PROTOCOLS-zh_Hans.md) · [Generation](README.md)

The authoritative schema is [proto/v1/ecaptureq.proto](proto/v1/ecaptureq.proto),
package `event`. The Go package is
`pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"`.
This protocol is used by `--ecaptureq`; raw `--eventaddr` bytes do not use it.

## Message framing and enums

Each binary WebSocket message is one encoded `LogEntry`. Dispatch by
`log_type` and check the matching `oneof payload` member:

| `LogType` | Value | Payload field | Meaning |
| --- | --- | --- | --- |
| `LOG_TYPE_HEARTBEAT` | 0 | `heartbeat_payload` (3) | Connection health |
| `LOG_TYPE_PROCESS_LOG` | 1 | `run_log` (4) | Operational log string |
| `LOG_TYPE_EVENT` | 2 | `event_payload` (2) | Captured event |

`LogEntry.log_type` is field 1. The payload members are mutually exclusive.
Unknown future enum values should not be treated as captured events.

| Enum | Values |
| --- | --- |
| `CaptureFormat` | `UNSPECIFIED=0`, `TEXT=1`, `KEYLOG=2`, `PCAPNG=3` (names prefixed with `CAPTURE_FORMAT_`) |
| `Sensitivity` | `NORMAL=0`, `SENSITIVE=1` (names prefixed with `SENSITIVITY_`) |

## Event

| Number | Field | Protobuf type | Current publisher semantics |
| --- | --- | --- | --- |
| 1 | `timestamp` | `int64` | Unix seconds |
| 2 | `uuid` | `string` | Module-supplied correlation identifier; not a guaranteed globally unique message ID |
| 3 | `src_ip` | `string` | Available source IP |
| 4 | `src_port` | `uint32` | Available source port |
| 5 | `dst_ip` | `string` | Available destination IP |
| 6 | `dst_port` | `uint32` | Available destination port |
| 7 | `pid` | `int64` | Available process ID |
| 8 | `pname` | `string` | Available process name |
| 9 | `type` | `uint32` | Internal domain event category, described below |
| 10 | `length` | `uint32` | Number of bytes in this `payload` |
| 11 | `payload` | `bytes` | Captured payload; format depends on the event representation |
| 12 | `capture_format` | `CaptureFormat` | Text, keylog, or packet representation |
| 13 | `sensitivity` | `Sensitivity` | Sensitive classification for keylog, packets, and reconstructed HTTP |
| 14 | `direction` | `string` | Producer-supplied direction when available; hook events use `read`/`write` |
| 15 | `original_length` | `uint32` | Original payload/packet length when available; otherwise a payload-length fallback |
| 16 | `stream_id` | `string` | Optional producer-supplied stream identity |
| 17 | `sequence` | `uint64` | Producer-local ordering metadata; not a global or persistent sequence |

`type` currently follows `internal/domain.EventType`: `0=Output`,
`1=ModuleData`, `2=Processor`. It is **not** an HTTP/1 or HTTP/2 request/response
enum. Module-private records can be consumed before publication, so enum
membership does not imply that a client will receive that category.

Metadata availability varies by probe and capture mode; zero/empty fields
must be handled. Sequences may reset after a probe reload, and UUIDs alone
must not be used to assume one-message uniqueness.

Text hook payloads can be captured bytes or a module text representation.
Keylog events carry secret material. Pcapng-format events carry packet payloads,
not complete pcapng blocks or files; DSB-only secret events are not emitted as
packet rows. The pcapng text source publishes reconstructed HTTP messages as
`TEXT` + `SENSITIVE`. See [output behavior](../docs/event-forward-api.md).

Fields 12–17 extend the existing v1 message. Older Protobuf readers ignore
unknown fields. A decoder receiving an older sender must tolerate their
zero/default values. UI-derived fields such as `is_binary` or `payload_utf8`
are not part of this schema.

## Heartbeat and delivery

`Heartbeat` has `int64 timestamp=1` (Unix seconds), `int64 count=2`, and
`string message=3`. The current server sends one immediately after connection
and every 15 seconds thereafter. `count` starts at zero for each connection;
it is a heartbeat counter, not an event-delivery count.

New clients receive at most the latest 128 `PROCESS_LOG` records, followed by
live logs. Captured `EVENT` messages are not retained for replay. Heartbeats
can interleave with history delivery. Bounded queues can report backpressure
and disconnect slow clients; there is no durable delivery or resume protocol.

For a complete receive/decode implementation, use the
[Go client example](../examples/ecaptureq_client/README.md). Check `log_type`
and the matching payload rather than trying to decode every message as `Event`.
