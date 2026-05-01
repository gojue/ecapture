# 远程事件流（eCaptureQ WebSocket）

## 概述

eCaptureQ 是 eCapture 内置的实时事件推送子系统，通过 WebSocket 协议将捕获的事件和日志流式传输给远程客户端。适用于需要集中收集和实时展示的场景。

## 工作原理

1. eCapture 启动时通过 `--ecaptureq` 参数开启 WebSocket 服务
2. 远程客户端通过 WebSocket 连接到 eCapture
3. eCapture 以 Protobuf 格式推送事件数据
4. 连接建立后，服务端会补发最近 128 条历史事件（启动缓存机制）

## 启动方式

```bash
# 启用 eCaptureQ WebSocket 服务
sudo ecapture tls --ecaptureq ws://0.0.0.0:28257
```

## Protobuf 消息格式

eCaptureQ 使用 Protocol Buffers 定义消息格式，定义文件位于 `protobuf/proto/v1/` 目录。

### 主要消息类型

| 消息类型 | 说明 |
|---------|------|
| `LogEntry` | 日志条目（包含时间戳、级别、消息内容） |
| `LogType` | 日志类型枚举 |
| `Heartbeat` | 心跳消息，保持连接活跃 |

### 128 条启动缓存

当新客户端连接时，eCaptureQ 会立即推送最近缓存的 128 条事件，确保客户端不会错过连接前短时间内的事件。

## 示例客户端

eCapture 提供了 Go 语言的示例客户端，位于 `examples/ecaptureq_client/` 目录。

### Go 客户端使用

```go
// 参见 examples/ecaptureq_client/ 目录的完整示例
```

### 多语言接入

eCaptureQ 基于标准 WebSocket + Protobuf 协议，任何支持这两种协议的语言都可以接入：

1. 建立 WebSocket 连接
2. 使用 Protobuf 反序列化接收到的二进制帧
3. 处理 `LogEntry` 消息

协议详细说明参见 `protobuf/PROTOCOLS-zh_Hans.md`。

## 源码参考

| 组件 | 路径 |
|------|------|
| WebSocket 服务端 | `pkg/ecaptureq/server.go` |
| Hub（连接管理） | `pkg/ecaptureq/hub.go` |
| 客户端 | `pkg/ecaptureq/client.go` |
| Protobuf 定义 | `protobuf/proto/v1/` |
| 生成代码 | `protobuf/gen/` |
| 示例客户端 | `examples/ecaptureq_client/` |
| WebSocket Writer | `internal/output/writers/websocket_writer.go` |
| IOWriter 适配器 | `internal/output/writers/iowriter_adapter.go` |
