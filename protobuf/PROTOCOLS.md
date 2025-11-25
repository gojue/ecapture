# eCapture Protobuf Protocol Overview

The `v1/ecaptureq.proto` file in this directory defines the core Protobuf protocol used between eCapture and external components (such as collectors and debugging tools).

## Namespaces and Generated Code

- **Proto Package Name:** `event`
- **Go Package Path:** `./pb` (see `option go_package = "./pb";`)
- **Source File Location:** `protobuf/proto/v1/ecaptureq.proto`
- **Generated Code Location:** `protobuf/gen/v1/ecaptureq.pb.go`

## Enum Types

### `LogType`

Used to identify the type of log entry:

- `LOG_TYPE_HEARTBEAT` (0): Heartbeat information, used for health checks and connection keep-alive.
- `LOG_TYPE_PROCESS_LOG` (1): Process execution logs, such as system events, error messages, etc.
- `LOG_TYPE_EVENT` (2): Actual captured business data events (e.g., TLS/HTTP data).

## Message Structures

### `Event`

A unified representation of a single event (packet/session fragment) captured by eCapture, corresponding to the Go struct `pb.Event`:

- `int64 timestamp`: Event timestamp.
- `string uuid`: Unique event identifier, used for correlation and deduplication.
- `string src_ip` / `uint32 src_port`: Source IP address and port.
- `string dst_ip` / `uint32 dst_port`: Destination IP address and port.
- `int64 pid`: Process ID.
- `string pname`: Process name, e.g., `curl`, `nginx`, etc.
- `uint32 type`: Event/Protocol type enum value:
  - `0`: Unknown
  - `1`: HTTP/1.x Request
  - `2`: HTTP/2 Request
  - `3`: HTTP/1.x Response
  - `4`: HTTP/2 Response
- `uint32 length`: Effective length of the `payload` (in bytes).
- `[]byte payload`: Actual payload data.

> **Note:** In the internal eCaptureQ backend model, fields such as `is_binary`, `payload_utf8`, and `payload_binary` are derived to distinguish between text/binary display. However, these are extension fields used internally by the server and UI, and do not appear directly in the Protobuf `Event` message.

### `Heartbeat`

Heartbeat message, used for connection keep-alive and statistics, corresponding to the Go struct `pb.Heartbeat`:

- `int64 timestamp`: Timestamp when the heartbeat was sent.
- `int64 count`: Heartbeat count or statistical values like cumulative event count.
- `string message`: Additional information (e.g., version number, status description, etc.).

### `LogEntry`

Top-level log encapsulation structure, uniformly carrying different types of business data:

- `LogType log_type`: Log type (`LOG_TYPE_HEARTBEAT` / `LOG_TYPE_PROCESS_LOG` / `LOG_TYPE_EVENT`).
- `oneof payload`: Carries one of the following three based on the `log_type`:
  - `Event event_payload`: Carries event data when `log_type = LOG_TYPE_EVENT`.
  - `Heartbeat heartbeat_payload`: Carries heartbeat information when `log_type = LOG_TYPE_HEARTBEAT`.
  - `string run_log`: Carries a standard execution log string when `log_type = LOG_TYPE_PROCESS_LOG`.

## Integration Example

This client can be used as a reference for integrating eCapture into other systems:

```go
import (
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
)

// Connect
ws, err := websocket.Dial("ws://127.0.0.1:28257/", "", "http://localhost/")
if err != nil {
	// Handle error
}
defer ws.Close()

// Receive messages
for {
	var msgData []byte
	err := websocket.Message.Receive(ws, &msgData)
	if err != nil {
		break
	}
	
	var logEntry pb.LogEntry
	err = proto.Unmarshal(msgData, &logEntry)
	if err != nil {
		continue
	}
	
	// Process logEntry based on logEntry.LogType
}
```