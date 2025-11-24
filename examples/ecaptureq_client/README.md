# eCapture WebSocket Client

This is a standalone Go client that connects to an eCapture WebSocket server (ecaptureq) to receive real-time events and logs.

## Overview

The eCapture WebSocket server (`--ecaptureq`) allows you to stream captured events in real-time using WebSocket protocol. This client demonstrates how to:

1. Connect to the WebSocket server
2. Receive and decode protobuf-encoded messages
3. Display events, logs, and heartbeats

## Building

```bash
cd examples/ecaptureq_client
go build -o ecaptureq_client main.go
```

Or from the repository root:

```bash
go build -o ecaptureq_client ./examples/ecaptureq_client
```

## Usage

### 1. Start eCapture with WebSocket server

First, start eCapture with the `--ecaptureq` parameter. The URL format should be `ws://HOST:PORT/`:

```bash
# Example: Listen on localhost port 28257
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/

# Example: Listen on all interfaces port 28257
# Note: Use a specific IP address, not 0.0.0.0
sudo ./ecapture tls --ecaptureq=ws://192.168.1.100:28257/
```

**Important Notes:**
- The server will listen on the HOST:PORT specified in the URL
- Use a specific IP address (like `127.0.0.1` or your machine's IP) instead of `0.0.0.0`
- The WebSocket endpoint is at the root path `/`

### 2. Run the client

```bash
# Connect to default server (ws://127.0.0.1:28257/)
./ecaptureq_client

# Connect to custom server
./ecaptureq_client -server ws://192.168.1.100:28257/

# Enable verbose logging (shows heartbeats)
./ecaptureq_client -server ws://127.0.0.1:28257/ -verbose
```

## Command-line Options

- `-server`: WebSocket server URL (default: `ws://127.0.0.1:28257/`)
- `-verbose`: Enable verbose logging, including heartbeat messages

## Message Types

The client handles three types of messages:

### 1. Heartbeat (LOG_TYPE_HEARTBEAT = 0)

Sent periodically by the server to keep the connection alive. Only displayed in verbose mode.

### 2. Process Log (LOG_TYPE_PROCESS_LOG = 1)

Log messages from the eCapture process itself, such as:
- Startup information
- Module initialization
- Configuration details
- Runtime status

### 3. Event (LOG_TYPE_EVENT = 2)

Captured SSL/TLS events containing:
- Timestamp
- UUID
- Process ID and name
- Source and destination IP/port
- Event type and length
- Payload data (displayed as text or hex dump)

## Example Output

```
Connecting to eCapture WebSocket server at ws://127.0.0.1:28257/
Connected successfully!
2025-01-15T10:30:45Z INF AppName="eCapture(旁观者)"
2025-01-15T10:30:45Z INF HomePage=https://ecapture.cc
2025-01-15T10:30:45Z INF Version=linux_amd64:v1.4.3-20250115:5.15.0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 Captured Event
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🆔 UUID:         12345_12345_curl_5_1_192.168.1.100:54870-180.101.49.44:443
🔢 PID:          12345
📝 Process:      curl
🔗 Source:       192.168.1.100:54870
🎯 Destination:  180.101.49.44:443
📊 Type:         1
📏 Length:       104 bytes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 Payload:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GET / HTTP/1.1
Host: www.baidu.com
Accept: */*
User-Agent: curl/7.81.0

Base64 encoded:
R0VUIC8gSFRUUC8xLjENCkhvc3Q6IHd3dy5iYWlkdS5jb20NCkFjY2VwdDogKi8qDQpVc2VyLUFnZW50OiBjdXJsLzcuODEuMA0KDQo=
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Protocol Details

The communication protocol uses Protocol Buffers (protobuf) with the following message structure:

```protobuf
message LogEntry {
  LogType log_type = 1;
  
  oneof payload {
    Event event_payload = 2;
    Heartbeat heartbeat_payload = 3;
    string run_log = 4;
  }
}
```

Where:
- `LogType` can be: `LOG_TYPE_HEARTBEAT` (0), `LOG_TYPE_PROCESS_LOG` (1), or `LOG_TYPE_EVENT` (2)
- Each message type has its specific payload structure

## Troubleshooting

### Connection Refused

If you get "connection refused" error:

1. Make sure eCapture is running with `--ecaptureq` parameter
2. Check that the server URL matches the one specified in eCapture command
3. Verify the port is not blocked by firewall
4. Ensure you're using the correct IP address (not 0.0.0.0)

### No Events Received

If connected but not receiving events:

1. Make sure eCapture is capturing traffic (check with `-d` debug flag)
2. Generate some SSL/TLS traffic (e.g., `curl https://www.baidu.com`)
3. Enable verbose mode to see heartbeat messages: `./ecaptureq_client -verbose`

### Bad Handshake

If you get "websocket: bad handshake" error:

1. Ensure the URL format is correct: `ws://HOST:PORT/` (with trailing slash)
2. Check that eCapture is actually listening (use `netstat -tlnp | grep PORT`)
3. Verify you're connecting to the correct port

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

## License

Same as eCapture - Apache License 2.0
