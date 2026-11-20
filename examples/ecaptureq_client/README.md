# Protobuf v2 receiver example

This Linux example connects to `--stream-listen` using WebSocket subprotocol
`ecapture.v2`. It validates every `LogEntry`, separates operational logs from
captured events, displays text metadata, and saves native keylog/pcapng streams.
It has no v1 fallback and does not reconnect automatically.

## Build and connect

This directory is a separate Go module. Its local replacement points at the
repository root. Build and test on Linux with Go 1.26.0 or newer:

```bash
cd examples/ecaptureq_client
go test -race ./...
go build -o ecaptureq_client .
```

On the capture host, start a built eCapture binary with the required privileges:

```bash
sudo ./bin/ecapture tls --model text --text-source pcapng \
  --stream-listen ws://127.0.0.1:28257/
```

Then connect the receiver:

```bash
./ecaptureq_client -server ws://127.0.0.1:28257/ -verbose
```

| Receiver option | Default | Meaning |
| --- | --- | --- |
| `-server` | `ws://127.0.0.1:28257/` | Protobuf v2 subscription URL |
| `-verbose` | `false` | Display transport heartbeat records |
| `-keylogfile` | empty | New file for a KEYLOG subscription |
| `-pcapfile` | empty | New file for a PCAPNG subscription |

The endpoint is disabled in eCapture until `--stream-listen` is set. The receiver
URL must be reachable from the receiver host; a server bind address such as
`0.0.0.0` is not a client destination. The listener is separate from
`--config-listen`, which accepts runtime configuration updates.

## Native capture streams

Start a pcapng collector with its own local artifact:

```bash
sudo ./bin/ecapture tls --model pcapng --pcapfile ./local.pcapng \
  --output ./runtime.jsonl --stream-listen ws://127.0.0.1:28257/
```

Save the subscription on the receiver host:

```bash
./ecaptureq_client -server ws://127.0.0.1:28257/ -pcapfile ./received.pcapng
```

For keylog mode use `--model keylog --keylogfile ./local.keys` on the collector
and `-keylogfile ./received.keys` on the receiver. Native data requires the
corresponding receiver file option; it is never silently printed or discarded.
Existing final or partial files are not overwritten. New files use mode `0600`.

The receiver first writes `NAME.partial`. A server close with code 1000 plus
successful native-format checks publishes `NAME`; abnormal close, interrupted
reception, malformed messages, or invalid native data leave `NAME.partial`.
The example checks keylog record syntax and pcapng block framing/packet presence.
These checks do not establish zero packet loss or successful TLS decryption.
The separate `gorilla/websocket` dependency lets the example distinguish close
1000 from an unexpected TCP EOF, which `x/net/websocket` does not expose.

Each subscription is one capture output session. A late pcapng subscriber receives
a fresh pcapng section and future packets/keys, not the collector's earlier local
file. Connections established before subscription may lack earlier handshakes or
keys. Keylog subscriptions also receive only future records. After a reload or
mode switch, reconnect explicitly with a new receiver filename; never append the
new connection to an earlier partial file.

## Message dispatch

```go
import (
    pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"
    protocol "github.com/gojue/ecapture/v2/protobuf/v2"
)
```

Decode one binary WebSocket message as `pb.LogEntry`, call
`protocol.ValidateLogEntry`, then dispatch on `log_type`:

- `PROCESS_LOG` goes to the status/log display.
- `HEARTBEAT` is transport health, not captured data.
- `EVENT` is dispatched by matching `capture_format` and `oneof content`.

`TextEvent` retains payload, process/network/TLS metadata, raw argv, and application
stream information. `KeylogEvent.data` contains standard NSS Key Log bytes.
`PcapngEvent.data` contains encoded pcapng bytes including headers, packet blocks,
TLS secrets blocks, and options. Concatenate native `data` in connection order:
message boundaries can split keylog lines or pcapng blocks. Never write operational
logs, heartbeats, Protobuf framing, or terminal prefixes into native files.

JSON TCP consumers use the same v2 schema through ProtoJSON; bytes are base64 in
JSON and must be decoded once. TCP consumers must frame records by newlines and
cannot treat a TCP read as one record. A raw TCP EOF alone does not prove that the
producer completed a capture.

The example exits when the connection ends, including failures. A text event's
metadata-only or empty payload is valid. Unknown log types, unknown capture
formats, inconsistent oneofs, and format switches within a connection are errors,
not fallback text.

See the [protocol reference](../../protobuf/PROTOCOLS.md) and
[event forwarding API](../../docs/event-forward-api.md). Core capture verification
uses the maintained Linux E2E harness; a successful connection or heartbeat does
not prove that capture works.
