# Event forwarding API

[中文](event-forward-api-zh_Hans.md)

Choose an output by the data your receiver needs. `--ecaptureq` and `--listen`
are disabled by default; the addresses below are examples, not default listeners.

| Option | Data | Connection direction |
| --- | --- | --- |
| `--logaddr` | eCapture operational logs, in addition to stderr | eCapture writes to a file/stdout or connects to a TCP/WebSocket receiver |
| `--eventaddr` | Captured-event bytes in the selected representation | eCapture writes to a file/stdout or connects to a TCP/WebSocket receiver |
| `--ecaptureq` | Typed Protobuf `LogEntry` messages: logs, events, heartbeats | eCapture listens; clients connect |

These outputs are additive. Enabling eCaptureQ does not replace `--eventaddr`.
Captured plaintext, TLS secrets, and packet payloads belong to event output;
`--logaddr` and eCaptureQ `PROCESS_LOG` carry operational records.

## Raw event destinations

For `tls`, `gotls`, and `gnutls`, capture mode selects the representation and
`--eventaddr` selects its destination:

| Mode | Byte stream | Default / compatibility |
| --- | --- | --- |
| `text --text-source=hook` | Hook event text | stdout when the destination is empty |
| `text --text-source=pcapng` | Reconstructed HTTP/1.1 or HTTP/2 messages | plaintext stdout; optional `--pcapfile` and `--keylogfile` artifacts |
| `keylog` | NSS Key Log lines | requires a destination after normalization; `--keylogfile` is the legacy primary-file alias |
| `pcap` / `pcapng` | pcapng packets with embedded TLS Decryption Secrets Blocks | requires a destination after normalization; `--pcapfile` is the legacy primary-file alias |

Current CLI legacy filename defaults remain supported. Explicitly setting
`--eventaddr` together with the corresponding primary legacy flag is an error.
In pcapng mode, `--keylogfile` instead selects an optional additional keylog file.
The pcapng text source uses packet capture and TLS secrets internally; HTTP/3
text reconstruction is not supported.

Destinations accept `stdout`, plain paths, `file://` paths, `tcp://host:port`,
`ws://host:port/path`, and `wss://host:port/path`. TCP is an ordered byte stream.
WebSocket uses binary messages; concatenate their payloads in arrival order to
reconstruct the stream. These bytes have no Protobuf wrapper. A connection
failure ends the stream; there is no automatic mid-artifact reconnect.

Rotation applies only to file-backed text/keylog output, not network sinks or
pcapng. Operational console logs use stderr, leaving pcapng stdout binary-only.
Explicit `--logaddr stdout` with pcapng `--eventaddr stdout` is rejected.

Run on a supported Linux/Android host with the required probe privileges:

```bash
# Separate event and operational files.
sudo ./bin/ecapture tls --eventaddr=/tmp/events.txt --logaddr=/tmp/ecapture.log

# A raw TCP receiver must already be listening.
sudo ./bin/ecapture tls -m keylog --eventaddr=tcp://127.0.0.1:9000

# Binary pcapng, including secrets, to stdout.
sudo ./bin/ecapture tls -m pcapng -i eth0 --eventaddr=stdout > /tmp/capture.pcapng
```

Choose the actual library/binary, interface, and capture filters for your target.
Raw keylogs and pcapng are sensitive artifacts.

## Typed eCaptureQ events

```bash
# File output and typed WebSocket publication run together.
sudo ./bin/ecapture tls --eventaddr=/tmp/events.txt \
  --ecaptureq=ws://127.0.0.1:28257/
```

The built-in listener accepts `ws://`; `wss://` support for raw sinks does not
add TLS to this server. A trailing slash is conventional, not required by the
CLI parser. `0.0.0.0` can be a bind address; clients use a reachable host address.
The built-in endpoint has no application authentication, so choose its exposure
accordingly.

Each binary WebSocket message contains one Protobuf `LogEntry`. Dispatch by
`log_type` and its matching payload:

- `HEARTBEAT`: per-connection health message, immediately on connection and
  then every 15 seconds.
- `PROCESS_LOG`: eCapture lifecycle and operational text. A new client receives
  at most the latest 128 such records, followed by live operational records.
- `EVENT`: captured data with representation, sensitivity, and available
  process/network metadata. Events are live-only and are not replayed.

Pcapng-format typed events describe packets; they are not chunks of a pcapng
file. Secret-only DSB records are not packet rows. Reconstructed HTTP events
from the pcapng text source use text format and sensitive classification.
Queues are bounded; a slow client may be disconnected and publication may
report backpressure. The protocol is not a durable delivery queue.

Use the [protocol reference](../protobuf/PROTOCOLS.md) for field semantics and
[Go client example](../examples/ecaptureq_client/README.md) for build, receive,
decode, and smoke-check steps. Other languages generate message types from
[ecaptureq.proto](../protobuf/proto/v1/ecaptureq.proto), read binary WebSocket
messages, and decode each independently.

See also [community integrations](event-forward.md),
[HTTP configuration updates](remote-config-update-api.md), and the
[output architecture](agent/output-pipeline.md).
