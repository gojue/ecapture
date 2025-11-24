## eCapture WebSocket API 文档

适用于 eCapture 的 WebSocket 接口，允许客户端连接到 eCapture 服务端以接收实时事件和日志。

### 连接方式

- **协议**：WebSocket
- **地址**：`ws://<server_host>:<server_port>/`

> 取决于 eCapture 的启动参数，比如：`sudo /usr/bin/ecapture tls --ecaptureq ws://192.168.71.123:28257/`
>
> **注意**：URL 必须包含尾部斜杠 `/`，且应使用具体的 IP 地址（如 `127.0.0.1` 或您的机器 IP），而不是 `0.0.0.0`

### 消息格式

所有消息均为 **Protocol Buffers (protobuf)** 编码格式，结构如下：

#### LogEntry (Protobuf)

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

#### 消息类型

| log_type              | 说明      | payload结构        |
|-----------------------|---------|------------------|
| 0 (LOG_TYPE_HEARTBEAT)  | 心跳包     | Heartbeat |
| 1 (LOG_TYPE_PROCESS_LOG) | 程序运行日志  | string (run_log)       |
| 2 (LOG_TYPE_EVENT)      | 捕获的事件详情 | Event           |

##### 心跳包

心跳包的`log_type` 为 0，表示心跳包，protobuf 结构：

```protobuf
message Heartbeat {
  int64 timestamp = 1;
  int64 count = 2;
  string message = 3;
}
```

##### 程序运行日志

当服务端发送程序运行日志时，`log_type` 为 1，`payload` 为 `run_log` 字符串字段，包含日志内容。

当客户端连接上服务端后，会收到服务端（即eCapture）发送的程序运行日志，比如：

```
2025-08-02T14:16:10Z INF AppName="eCapture(旁观者)"
2025-08-02T14:16:10Z INF HomePage=https://ecapture.cc
2025-08-02T14:16:10Z INF Repository=https://github.com/gojue/ecapture
2025-08-02T14:16:10Z INF Author="CFC4N <cfc4ncs@gmail.com>"
2025-08-02T14:16:10Z INF Description="Capturing SSL/TLS plaintext without a CA certificate using eBPF. Supported on Linux/Android kernels for amd64/arm64."
2025-08-02T14:16:10Z INF Version=linux_arm64:v1.3.1-20250629-b395562:5.15.0-143-generic
2025-08-02T14:16:10Z INF Listen=localhost:28256
2025-08-02T14:16:10Z INF Listen for eCaptureQ=ws://172.16.71.129:9999
```

> 即使eCapture先启动，客户端连接后也会收到这些日志。 是因为eCapture在启动时会缓存前128条日志，连接后会将这些日志发送给客户端。

##### 捕获的事件详情

当服务端捕获到 hook 事件时，会以 `log_type: 2` 的消息推送事件详情，`payload` 为 `event_payload` 字段。

Protobuf 结构：

```protobuf
message Event {
  int64 timestamp = 1;
  string uuid = 2;
  string src_ip = 3;
  uint32 src_port = 4;
  string dst_ip = 5;
  uint32 dst_port = 6;
  int64 pid = 7;
  string pname = 8;
  uint32 type = 9;
  uint32 length = 10;
  bytes payload = 11;
}
```

---

## Client 实现示例（Go 语言）

我们提供了一个完整的 WebSocket 客户端实现示例，位于 `examples/ecaptureq_client` 目录。

### 快速开始

```bash
# 构建客户端
cd examples/ecaptureq_client
go build -o ecaptureq_client main.go

# 连接到 eCapture 服务器
./ecaptureq_client -server ws://127.0.0.1:28257/
```

### 核心代码片段

```go
package main

import (
	pb "github.com/gojue/ecapture/protobuf/gen/v1"
	"golang.org/x/net/websocket"
	"google.golang.org/protobuf/proto"
)

func main() {
	// 连接到 WebSocket 服务器
	ws, err := websocket.Dial("ws://127.0.0.1:28257/", "", "http://localhost/")
	if err != nil {
		panic(err)
	}
	defer ws.Close()

	// 接收消息
	for {
		var msgData []byte
		err := websocket.Message.Receive(ws, &msgData)
		if err != nil {
			break
		}

		// 解码 protobuf 消息
		var logEntry pb.LogEntry
		err = proto.Unmarshal(msgData, &logEntry)
		if err != nil {
			continue
		}

		// 处理不同类型的消息
		switch logEntry.LogType {
		case pb.LogType_LOG_TYPE_HEARTBEAT:
			hb := logEntry.GetHeartbeatPayload()
			// 处理心跳...
		case pb.LogType_LOG_TYPE_PROCESS_LOG:
			log := logEntry.GetRunLog()
			// 处理日志...
		case pb.LogType_LOG_TYPE_EVENT:
			event := logEntry.GetEventPayload()
			// 处理事件...
		}
	}
}
```

完整实现请参考 `examples/ecaptureq_client/` 目录，包含详细的文档和使用说明。

---

## 说明

1. 客户端通过 WebSocket 连接到服务端，持续读取消息。
2. 消息使用 **Protocol Buffers** 编码，需要使用 `protobuf/gen/v1` 包中的定义进行解码。
3. 根据 `log_type` 字段判断消息类型，分别处理心跳、日志和事件。
4. 事件详情通过 `log_type: 2` 推送，`event_payload` 中的 `payload` 字段是原始字节数组，包含捕获的数据内容。