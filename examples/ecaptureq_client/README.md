# eCaptureQ Go client example

This client reads binary Protobuf messages from an eCapture `--ecaptureq`
listener. It prints operational logs and captured events, including available
process/network metadata, format, sensitivity, direction, and payload in
text/hex plus base64. `-verbose` also displays heartbeats.

## Build and connect

Use Linux and Go 1.26.0 or newer. This directory is a separate Go module;
its `go.mod` replaces `github.com/gojue/ecapture/v2` with the repository root.
Build from this directory, not with `go build ./examples/ecaptureq_client`
from the root module:

```bash
cd examples/ecaptureq_client
go build -o ecaptureq_client .
```

In another terminal, from the repository root, start a built eCapture binary
on a supported capture host with the required probe privileges:

```bash
sudo ./bin/ecapture tls --ecaptureq=ws://127.0.0.1:28257/
```

Then, in the client directory:

```bash
./ecaptureq_client -server ws://127.0.0.1:28257/ -verbose
```

| Client flag | Default | Purpose |
| --- | --- | --- |
| `-server` | `ws://127.0.0.1:28257/` | WebSocket URL to connect to |
| `-verbose` | `false` | Show heartbeats |

The client URL default does not enable a server listener: eCapture's
`--ecaptureq` and HTTP `--listen` are disabled unless explicitly configured.
The server accepts `ws://`; a trailing `/` is conventional, not mandatory in
the CLI. `0.0.0.0` is a possible bind address; remote clients use a reachable
server address. The built-in server has no application authentication or TLS.

## Manual smoke checks

These checks verify client behavior; use the [maintained E2E harness](../../test/e2e/README.md) for capture, decryption,
and strict typed-message assertions.

1. **Connection and history:** connect after eCapture starts. Expect operational
   logs (at most the latest 128), followed by live logs. Historical captured
   events are not replayed.
2. **Heartbeat:** with `-verbose`, expect an immediate heartbeat and then one
   every 15 seconds. Counts start at zero for each client connection.
3. **Captured data:** generate known TLS traffic from an application using the
   OpenSSL/BoringSSL library selected by the running probe. Confirm the expected
   content appears as an event. A connection or heartbeat alone is not evidence
   that capture works. For GoTLS/GnuTLS, start the matching probe and workload.
4. **Multiple clients:** connect two clients before generating new traffic.
   Under normal load both should receive the live events. Events produced before
   a client connects are not replayed; bounded queues can disconnect slow clients.
5. **Disconnect:** stop eCapture and confirm `Connection closed` is reported.
   The example does not reconnect automatically. Its main goroutine still waits
   for a signal after the receiver exits, so press Ctrl+C to end the process.
6. **Client shutdown:** Ctrl+C closes the client connection. Other connected
   clients should continue receiving live messages.

Raw event output can be checked alongside this client by starting eCapture
with an additional `--eventaddr=/tmp/events.txt`. Typed pcapng events contain
packet payloads, not a reconstructable pcapng file; use the raw destination
when a file artifact is needed.

## Integrating the receive loop

The complete implementation is in [main.go](main.go). It uses:

```go
import (
    pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"
    "golang.org/x/net/websocket"
    "google.golang.org/protobuf/proto"
)
```

Read each WebSocket message into `[]byte`, unmarshal one `pb.LogEntry`, then
dispatch by `LogType` and its matching payload. Keep `PROCESS_LOG` and captured
`EVENT` data separate. Handle empty metadata and unknown enum values.
See the [protocol reference](../../protobuf/PROTOCOLS.md) for field semantics.

## Troubleshooting

- **Connection refused / bad handshake:** confirm eCapture started successfully,
  the `--ecaptureq` listener is enabled, and the client's host/port matches it.
  The raw `--eventaddr` WebSocket sink is an outgoing connection, not this server.
- **Connected but no events:** verify target library/ELF, PID/UID filters, probe
  startup, and actual traffic. Heartbeats only prove connection health.
- **Decode errors:** use the current schema and ensure the endpoint sends typed
  eCaptureQ messages rather than raw event bytes.
- **Connection closed:** inspect server/probe errors and client backpressure;
  restart the example manually after correcting the cause.

For output modes and listener behavior, see the
[event forwarding API](../../docs/event-forward-api.md).
