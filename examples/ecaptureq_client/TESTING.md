# Testing the eCapture WebSocket Client

This guide helps you test the ecaptureq WebSocket client with a running eCapture instance.

## Prerequisites

- Linux system with kernel 5.10+ (for eCapture)
- Root/sudo access
- Go 1.24+ installed
- eCapture binary built

## Step-by-Step Testing Guide

### 1. Build the Client

```bash
cd examples/ecaptureq_client
go build -o ecaptureq_client main.go
```

### 2. Start eCapture Server

In one terminal, start eCapture with the `--ecaptureq` parameter:

```bash
# Option A: Listen on localhost (most secure for testing)
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/

# Option B: Listen on specific network interface
sudo ./ecapture tls --ecaptureq=ws://192.168.1.100:28257/
```

**Important Notes:**
- URL **must** end with `/` (trailing slash)
- Use specific IP like `127.0.0.1` or your machine's IP
- Do **NOT** use `0.0.0.0` - it won't work!
- Default management port is also started on `localhost:28256`

You should see output like:
```
2025-01-15T10:30:45Z INF AppName="eCapture(旁观者)"
2025-01-15T10:30:45Z INF Listen for eCaptureQ=ws://127.0.0.1:28257
```

### 3. Verify Server is Listening

In another terminal, check that the WebSocket port is listening:

```bash
netstat -tlnp | grep 28257
# Should show:
# tcp  0  0  127.0.0.1:28257  0.0.0.0:*  LISTEN  <pid>/ecapture
```

If you don't see this, check:
- eCapture started without errors
- URL format is correct (with trailing `/`)
- You're not using `0.0.0.0`

### 4. Connect the Client

In a third terminal, run the client:

```bash
cd examples/ecaptureq_client

# Basic connection
./ecaptureq_client -server ws://127.0.0.1:28257/

# With verbose mode (shows heartbeats)
./ecaptureq_client -server ws://127.0.0.1:28257/ -verbose
```

You should immediately see:
```
Connecting to eCapture WebSocket server at ws://127.0.0.1:28257/
Connected successfully!
2025-01-15T10:30:45Z INF AppName="eCapture(旁观者)"
2025-01-15T10:30:45Z INF HomePage=https://ecapture.cc
...
```

### 5. Generate Test Traffic

Now generate some SSL/TLS traffic to capture:

```bash
# In a fourth terminal
curl https://www.baidu.com
curl https://www.google.com
wget https://www.github.com
```

### 6. Observe Captured Events

In the client terminal, you should see captured events like:

```
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

## Troubleshooting

### "Failed to connect to WebSocket server"

**Cause:** Server not running or wrong URL

**Solutions:**
1. Check eCapture is running: `ps aux | grep ecapture`
2. Check port is listening: `netstat -tlnp | grep 28257`
3. Verify URL format has trailing `/`
4. Make sure you're using the same IP/port as eCapture

### "websocket: bad handshake"

**Cause:** URL format issue or server not ready

**Solutions:**
1. Ensure URL ends with `/`: `ws://127.0.0.1:28257/` ✅ not `ws://127.0.0.1:28257` ❌
2. Wait a second after starting eCapture before connecting
3. Check firewall isn't blocking the port

### Connected but no events

**Cause:** No traffic to capture or wrong filters

**Solutions:**
1. Generate test traffic: `curl https://www.baidu.com`
2. Check eCapture is capturing: look for events in eCapture terminal
3. Try verbose mode: `./ecaptureq_client -verbose` to see heartbeats
4. Check eCapture started without errors

### "Connection closed: EOF"

**Cause:** eCapture terminated or network issue

**Solutions:**
1. Check if eCapture process is still running
2. Restart both eCapture and client
3. Check system logs for errors

## Testing Different Scenarios

### Test 1: Localhost Connection
```bash
# Terminal 1
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/

# Terminal 2
./ecaptureq_client -server ws://127.0.0.1:28257/

# Terminal 3
curl https://www.baidu.com
```

### Test 2: Network Connection
```bash
# Terminal 1 (on server machine, IP 192.168.1.100)
sudo ./ecapture tls --ecaptureq=ws://192.168.1.100:28257/

# Terminal 2 (on client machine or same machine)
./ecaptureq_client -server ws://192.168.1.100:28257/

# Terminal 3
curl https://www.github.com
```

### Test 3: Verbose Mode with Heartbeats
```bash
# Terminal 1
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/

# Terminal 2
./ecaptureq_client -server ws://127.0.0.1:28257/ -verbose

# You should see heartbeat messages every 60 seconds
```

### Test 4: Multiple Clients
```bash
# Terminal 1
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/

# Terminal 2
./ecaptureq_client -server ws://127.0.0.1:28257/

# Terminal 3
./ecaptureq_client -server ws://127.0.0.1:28257/

# Both clients receive the same events!
```

## Expected Behavior

1. **Connection**: Client connects immediately and receives buffered logs (up to 128 entries)
2. **Heartbeats**: Server sends heartbeat every 60 seconds (visible with `-verbose`)
3. **Events**: All captured SSL/TLS events are broadcast to all connected clients
4. **Logs**: Process logs are sent as they occur

## Performance Notes

- Multiple clients can connect simultaneously
- All clients receive the same events (broadcast)
- Events are sent in real-time (not buffered)
- Initial connection receives last 128 log entries
- Heartbeat keeps connection alive

## Integration Testing

To integrate this into your own application:

```go
// See main.go for full example
import (
    pb "github.com/gojue/ecapture/protobuf/gen/v1"
    "golang.org/x/net/websocket"
    "google.golang.org/protobuf/proto"
)

ws, _ := websocket.Dial("ws://127.0.0.1:28257/", "", "http://localhost/")
defer ws.Close()

for {
    var msgData []byte
    websocket.Message.Receive(ws, &msgData)
    
    var logEntry pb.LogEntry
    proto.Unmarshal(msgData, &logEntry)
    
    // Handle logEntry based on logEntry.LogType
}
```

## Clean Up

When done testing:

1. Stop the client: Press `Ctrl+C`
2. Stop eCapture: Press `Ctrl+C` in the eCapture terminal
3. Clean up built binaries if desired:
   ```bash
   rm examples/ecaptureq_client/ecaptureq_client
   ```

## Questions?

If you encounter issues not covered here, please:
1. Check the main README.md in this directory
2. Check the pkg/ecaptureq/README.md
3. Open an issue on GitHub with details of your setup and error messages
