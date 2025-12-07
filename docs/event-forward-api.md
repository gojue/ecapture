# eCapture Event Forwarding API

This document briefly explains **how to receive events and runtime logs from eCapture as a client**, and where to find the detailed protocol and demo code in this repository.

> Notes:
> 
> - Default listening address: `ws://127.0.0.1:28257`
> - The listening address can be modified via the `--ecaptureq` command-line argument, for example: `--ecaptureq=ws://127.0.0.1:28257/`
> - All interfaces are **Protobuf**

eCapture exposes three parameters related to log / event output:

- `--logaddr`: output for **eCapture runtime logs** (text)
- `--eventaddr`: output for **captured events** (text)
- `--ecaptureq`: WebSocket + Protobuf(LogEntry) endpoint for streaming **runtime logs and events** (structured)

The repository already contains detailed protocol docs and a full demo client.  
This file is intentionally concise and mainly serves as an **index + behavior overview**.

---

## 1. Output parameters and priority

### 1.1 `--logaddr`: runtime logs (text)

- Purpose: specify where **eCapture’s own runtime logs** are written.
- Supported targets:
    - File path (e.g. `/var/log/ecapture.log`)
    - `tcp://host:port`
    - `ws://host:port/path` or `wss://host:port/path`
- Content: initialization info, module startup, configuration details, errors, etc.  
  Format: **plain text**.

### 1.2 `--eventaddr`: captured events (text)

- Purpose: specify where **captured event logs** are written.
- Supported targets: similar to `--logaddr` (file / TCP / WebSocket), but output is **text-formatted event logs**.
- Typical use cases:
    - Directly writing events into files, TCP streams, or an existing log pipeline;
    - When your downstream system prefers plain text logs and does not need protobuf parsing yet.

### 1.3 `--ecaptureq`: unified event forwarding (WebSocket + Protobuf)

- Purpose: start a **WebSocket server** (eCaptureQ) and stream both **runtime logs and captured events** as structured `LogEntry` Protobuf messages.
- Example:

  ```bash
  # Start eCaptureQ on localhost:28257
  sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/
  ```

- Characteristics:
    - Clients connect via WebSocket;
    - Each message is a binary Protobuf-encoded `LogEntry`;
    - The `log_type` field distinguishes heartbeat / process log / event.

### 1.4 Relationship between `eventaddr` and `ecaptureq`

Both parameters define “event output channels”:

- `--eventaddr`: event logs in **plain text format**;
- `--ecaptureq`: events + logs in **Protobuf(LogEntry)** format via WebSocket.

**Priority:**

- If **both `--ecaptureq` and `--eventaddr` are set**, eCapture will **prefer `--ecaptureq`** for streaming events.
- You can think of it as:
    - For **structured, programmatically consumable** event streams → use `--ecaptureq`;
    - For **plain text log output** → use `--eventaddr`.

---

## 2. Using eCaptureQ WebSocket (recommended)

If you want real-time, structured events via WebSocket + Protobuf, use `--ecaptureq` and refer to the existing protocol docs and demo client.

### 2.1 Protocol and message structure

Please read:

- Protobuf definition:  
  `protobuf/proto/v1/ecaptureq.proto`
- Protocol overview:  
  `protobuf/PROTOCOLS.md`

Together they define:

- Top-level message `LogEntry`:

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

- `LogType` enum:
    - `LOG_TYPE_HEARTBEAT` – heartbeat messages;
    - `LOG_TYPE_PROCESS_LOG` – eCapture runtime logs;
    - `LOG_TYPE_EVENT` – captured business events (e.g. TLS/HTTP data).
- `Event` fields:
    - `timestamp`, `uuid`, `src_ip`, `dst_ip`, `pid`, `pname`, `type`, `length`, `payload`, etc.
- `Heartbeat` fields:
    - `timestamp`, `count`, `message`.

`PROTOCOLS.md` provides detailed semantics for each field; use it as the main reference when integrating.

### 2.2 Official Go demo client

If you use Go, the easiest approach is to reuse the official demo:

- Directory: `examples/ecaptureq_client/`
    - Code: `examples/ecaptureq_client/main.go`
    - Usage: `examples/ecaptureq_client/README.md`

The demo already implements:

1. Connecting to the WebSocket server specified by `--ecaptureq`;
2. Continuously reading binary messages;
3. Decoding them into `pb.LogEntry` (under `protobuf/gen/v1`);
4. Handling message types by `LogType`:
    - printing runtime logs;
    - displaying captured events in a human-friendly way (including payload text/hex/base64);
    - optionally showing heartbeats in verbose mode.

#### Quick start with the demo

```bash
# 1. Start eCapture with eCaptureQ enabled
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/

# 2. Build the client
cd examples/ecaptureq_client
go build -o ecaptureq_client main.go

# 3. Connect and watch events
./ecaptureq_client -server ws://127.0.0.1:28257/
# or
./ecaptureq_client -server ws://192.168.1.100:28257/ -verbose
```

If you want to integrate this into your own system:

- Copy the core receive + decode + dispatch logic from `main.go`;
- Replace “print to terminal” with writing to your storage, message queue, or analytics engine.

### 2.3 Integrating from other languages

For other languages (Python / Java / Node.js / Rust / …), the pattern is:

1. Use that language’s Protobuf tooling to generate types from  
   `protobuf/proto/v1/ecaptureq.proto`.
2. Use a WebSocket client library to connect to `ws://HOST:PORT/`  
   (note: the URL must end with `/`).
3. In a loop:
    - read a binary message from WebSocket;
    - decode it into `LogEntry`;
    - handle it based on `log_type` (heartbeat / process log / event).

You can first run `examples/ecaptureq_client` to observe real traffic and then mirror the same logic in your language of choice.

---

## 3. Using `eventaddr` / `logaddr` for plain text logs

If you don’t want to deal with Protobuf and just need **plain text logs**:

- Use `--logaddr` for eCapture runtime logs;
- Use `--eventaddr` for captured event logs (text).

Examples:

```bash
# Runtime logs to one file, event logs to another
./ecapture tls \
  --logaddr=/var/log/ecapture.log \
  --eventaddr=/var/log/ecapture-events.log
```

or:

```bash
# Send event logs via TCP to a remote service
./ecapture tls \
  --eventaddr=tcp://192.168.1.100:9000
```

In this mode, as a “client” you only need to:

- Read from the configured file or TCP stream;
- Parse lines (or whatever text format was chosen) as logs/events.

**Reminder:** If you set both `--ecaptureq` and `--eventaddr`, events will be streamed **via `--ecaptureq` first** (WebSocket + Protobuf).  
`eventaddr` is mainly useful when you are **not** using eCaptureQ and just need text logs.

---

## 4. Summary

- For **structured, programmatic** consumption of events:
    - Use `--ecaptureq`, and refer to:
        - `protobuf/proto/v1/ecaptureq.proto`
        - `protobuf/PROTOCOLS.md`
        - `examples/ecaptureq_client/`
- For **plain text logs**:
    - Use `--logaddr` for runtime logs;
    - Use `--eventaddr` for event logs (no Protobuf).
- When both are configured, `--ecaptureq` has the **highest priority** and is used first to forward events and logs over WebSocket + Protobuf.

This document stays minimal on purpose.  
For full details, always refer to the protocol docs and the demo client in this repository.