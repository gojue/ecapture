# Protobuf v2 订阅监听服务

`internal/output/stream`（Go 包名 `stream`）是 eCapture 内部的订阅监听服务，
为核心 TLS、GoTLS、GnuTLS 发布运行日志、捕获事件和心跳。
它与独立的 eCaptureQ 客户端产品是不同组件。
CLI 使用 `--stream-listen ws://127.0.0.1:28257/` 启用监听，默认关闭；
客户端必须协商 `ecapture.v2`。旧 `--ecaptureq` 参数直接删除，没有别名或 v1 fallback。
本次包路径调整不改变 CLI 参数、Protobuf schema 或 WebSocket 子协议。

## 接入

- [输出 API](../../../docs/event-forward-api-zh_Hans.md)：重复 `--output`、输出矩阵和连接方向。
- [协议参考](../../../protobuf/PROTOCOLS-zh_Hans.md)：v2 oneof、原生字节和会话完整性。
- [Go 接收端](../../../examples/ecaptureq_client/README.md)：正常关闭识别及 `.partial` 原生文件保存。
- [Schema](../../../protobuf/proto/v2/ecaptureq.proto) 和[代码生成](../../../protobuf/README-zh_Hans.md)。

Go 消费端导入 `pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"`。
每个 WS binary message 是一个 LogEntry，先校验 log_type 和 oneof，再按 capture_format 分流。
TEXT 保留全部元数据；KEYLOG/PCAPNG 的 data 是可直接拼接的编码器原生字节。
不要把运行日志、心跳、终端前缀或 Protobuf 外壳写入原生文件。

监听器仅提供 WS，不提供 TLS 或应用层认证。URL path 为订阅路径；
`0.0.0.0` 可用于绑定，客户端应使用可达地址。输出目的端与配置更新监听都属于进程级依赖，
HTTP 更新不能修改。例子：

```bash
sudo ./bin/ecapture tls --model text --text-source pcapng \
  --output stdout --output /tmp/records.jsonl \
  --stream-listen ws://127.0.0.1:28257/
```

## 包内职责

`NewServer(addr, logWriter)` 使用 `host:port`，`NewServerWithPath` 可指定订阅路径。
`Start` 阻塞服务，`StartAsync` 成功绑定后返回错误通道；CLI 持有监听器并跨重载复用。

- `BeginCapture` 开始一代捕获；未激活捕获时拒绝新订阅。
- `PublishLog` 只发布运行日志，最近最多 128 条可供新订阅回放。
- `PublishEvent` 发布 TEXT，`PublishKeylog` 发布已编码 NSS 字节，`PublishPacket` 提供原生 pcapng 编码输入。
- 每个 pcapng 客户端拥有独立编码 session，先发送新头部，随后仅发送未来包和密钥；不回放历史秘密。
- `EndCapture` 刷新编码器并排空队列后关闭连接，正常 Close 1000；`AbortCapture` 标记失败，客户端须保留 partial。
- `Hub` 串行管理订阅、运行日志历史和消息交付；不缓存事件。队列满返回 `ErrBackpressure`，慢客户端可能被断开。
- `Client` 连接后立即发送心跳，随后每 15 秒发送。`DroppedMessages()` 暴露丢弃计数。

一条连接仅属于一个 capture generation；重载后重新连接并使用新原生文件。
晚连片段不等于完整本地文件，缺少旧握手/密钥时无法保证解密已有 TLS 连接。
原生编码失败、慢客户端或断开均不能宣称文件完整。TCP EOF 不提供应用层成功信号；
WS 接收端也必须确认 Close 1000，并完成本地文件检查后再移除 `.partial` 后缀。

本包实现 `internal/domain` 的发布接口，不是通用 ByteSink。外部模块应依赖公开协议类型，
不能导入本仓库 internal 包。维护时核对[输出架构](../../../docs/agent/output-pipeline.md)和本目录测试。
