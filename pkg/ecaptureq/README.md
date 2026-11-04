# eCaptureQ WebSocket 发布包

本包为 eCapture 提供类型化运行日志和捕获事件发布。
CLI 通过 `--ecaptureq=ws://127.0.0.1:28257/` 启用监听，默认关闭。
它与 `--eventaddr` 的原始 text/keylog/pcapng 输出可以同时工作。

## 接入入口

- [事件转发 API](../../docs/event-forward-api-zh_Hans.md)：选择输出、连接方向、原始字节与类型化消息的区别。
- [协议字段参考](../../protobuf/PROTOCOLS-zh_Hans.md)：`LogEntry`、枚举和完整 `Event` 字段。
- [Go 客户端示例](../../examples/ecaptureq_client/README.md)：独立模块构建、运行及手工检查。
- [协议源文件](../../protobuf/proto/v1/ecaptureq.proto)与[生成方法](../../protobuf/README-zh_Hans.md)。

监听器只接受 CLI 的 `ws://` 配置；它不提供 TLS 或应用层认证。
尾部 `/` 不由 CLI 强制要求，`0.0.0.0` 可以用于绑定；客户端连接实际可达的地址。
Go 消费者导入 `github.com/gojue/ecapture/v2/protobuf/gen/v1`，包名为 `pb`。

## 包内职责

`NewServer(addr, logWriter)` 接受 `host:port` 监听地址。
`Start` 阻塞服务，`StartAsync` 在绑定成功后返回错误通道，`Close` 可重复调用。
CLI 创建并持有服务器，把它作为进程级依赖跨探针重载复用。

- `PublishLog` 发布 `PROCESS_LOG`，只接受运行日志。
- `PublishEvent` 发布 `EVENT`，从领域事件信封生成 Protobuf，不反向解析输出文件。
- `Hub` 串行处理订阅、有限历史及广播；只保留最近最多 128 条运行日志，不缓存捕获事件。
- `Client` 负责读写连接；连接后立即发送心跳，随后每 15 秒发送。
- 队列满会返回 `ErrBackpressure` 并增加 `DroppedMessages()` 计数；慢客户端可能被断开。

它实现 `internal/domain` 的日志与事件发布接口，不是 `io.Writer`/ByteSink。
外部客户端应依赖公开的生成协议类型；仓库外的 Go 模块不能直接导入 `internal/domain`。

维护变更时还需核对[输出架构](../../docs/agent/output-pipeline.md)及本目录测试。
