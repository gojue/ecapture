# eCapture Protobuf 协议总览

本目录中的 `v1/ecaptureq.proto` 定义了 eCapture 与外部组件（如收集器、调试工具）之间使用的核心 Protobuf 协议。

## 命名空间与生成代码

- Proto 包名：`event`
- Go 包路径：`./pb`（参见 `option go_package = "./pb";`）
- 源文件位置：`protobuf/proto/v1/ecaptureq.proto`
- 生成代码位置：`protobuf/gen/v1/ecaptureq.pb.go`

## 枚举类型

### `LogType`

用于标识日志条目的类型：

- `LOG_TYPE_HEARTBEAT` (0)：心跳信息，用于健康检查和连接保活。
- `LOG_TYPE_PROCESS_LOG` (1)：进程运行日志，例如系统事件、错误信息等。
- `LOG_TYPE_EVENT` (2)：实际捕获到的业务数据事件（如 TLS/HTTP 数据）。

## 消息结构

### `Event`

eCapture 捕获到的单条事件（数据包/会话片段）的统一表示，对应 Go 结构体 `pb.Event`：

- `int64 timestamp`：事件时间戳。
- `string uuid`：事件唯一标识，用于关联与去重。
- `string src_ip` / `uint32 src_port`：源 IP 地址和端口。
- `string dst_ip` / `uint32 dst_port`：目标 IP 地址和端口。
- `int64 pid`：进程 ID。
- `string pname`：进程名称，例如 `curl`、`nginx` 等。
- `uint32 type`：事件/协议类型枚举值：
  - `0`：Unknown
  - `1`：HTTP/1.x Request
  - `2`：HTTP/2 Request
  - `3`：HTTP/1.x Response
  - `4`：HTTP/2 Response
- `uint32 length`：`payload` 的有效长度（字节数）。
- `[]byte payload`：实际载荷数据。

> 说明：在 eCaptureQ 后端内部模型中，还会派生出 `is_binary`、`payload_utf8`、`payload_binary` 等字段，用于区分文本/二进制展示，但这些是服务端内部和 UI 使用的扩展字段，不直接出现在 Protobuf `Event` 消息中。

### `Heartbeat`

心跳消息，用于连接保活和统计信息，对应 Go 结构体 `pb.Heartbeat`：

- `int64 timestamp`：发送心跳的时间戳。
- `int64 count`：心跳计数或累计事件数量等统计值。
- `string message`：附加信息（如版本号、状态描述等）。

### `LogEntry`

顶层日志封装结构，统一承载不同类型的业务数据：

- `LogType log_type`：日志类型（`LOG_TYPE_HEARTBEAT` / `LOG_TYPE_PROCESS_LOG` / `LOG_TYPE_EVENT`）。
- `oneof payload`：根据 `log_type` 不同，携带以下三种之一：
  - `Event event_payload`：当 `log_type = LOG_TYPE_EVENT` 时，承载事件数据。
  - `Heartbeat heartbeat_payload`：当 `log_type = LOG_TYPE_HEARTBEAT` 时，承载心跳信息。
  - `string run_log`：当 `log_type = LOG_TYPE_PROCESS_LOG` 时，承载普通运行日志字符串。

## 集成示例

此客户端可作为将 eCapture 集成到其他系统的参考：

```go
import (
  pb "github.com/gojue/ecapture/protobuf/gen/v1"
  "golang.org/x/net/websocket"
  "google.golang.org/protobuf/proto"
)

// Connect (连接)
ws, err := websocket.Dial("ws://127.0.0.1:28257/", "", "http://localhost/")
if err != nil {
  // Handle error (处理错误)
}
defer ws.Close()

// Receive messages (接收消息)
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
  // 根据 logEntry.LogType 处理日志条目
}
```