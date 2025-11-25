# eCapture Protobuf Debugger

A visualization and debugging tool for eCapture WebSocket messages.
It supports parsing Protobuf messages of type **Event**, **Heartbeat**, and **Log**.

## Build

```bash
go build -o pb_debugger pb_debugger.go
```

## Usage

### Common commands

```bash
# Connect to the default address (ws://127.0.0.1:28257)
./pb_debugger

# Specify WebSocket server address
./pb_debugger -url ws://192.168.1.100:28257

# Compact mode (single-line output, suitable for high‑frequency data)
./pb_debugger -compact

# Hex mode (inspect raw payload bytes)
./pb_debugger -hex

# Save output to file (color automatically disabled)
./pb_debugger -no-color > capture.log
```

### Command-line flags

| Flag            | Default                | Description                               |
|-----------------|------------------------|-------------------------------------------|
| `-url`          | `ws://127.0.0.1:28257` | WebSocket server address                  |
| `-compact`      | `false`                | Enable single-line compact output mode    |
| `-hex`          | `false`                | Show payload in hex format                |
| `-max-payload`  | `1024`                 | Maximum number of payload bytes to show   |
| `-no-color`     | `false`                | Disable colored output in the terminal    |
