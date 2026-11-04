# 事件转发 API

[English](event-forward-api.md)

按接收端需要的数据选择输出。`--ecaptureq` 和 `--listen` 默认关闭；下文地址是示例，不是默认监听地址。

| 参数 | 数据内容 | 连接方向 |
| --- | --- | --- |
| `--logaddr` | eCapture 运行日志，stderr 仍保留输出 | eCapture 写文件/stdout，或连接 TCP/WebSocket 接收端 |
| `--eventaddr` | 所选表示格式的捕获事件字节流 | eCapture 写文件/stdout，或连接 TCP/WebSocket 接收端 |
| `--ecaptureq` | Protobuf `LogEntry`：运行日志、事件、心跳 | eCapture 监听，客户端连接 |

三者可以同时输出。启用 eCaptureQ 不会替代 `--eventaddr`。
捕获明文、TLS 密钥和数据包属于事件输出；`--logaddr` 与 eCaptureQ 的 `PROCESS_LOG` 只承载运行日志。

## 原始事件输出

对于 `tls`、`gotls`、`gnutls`，捕获模式决定表示格式，`--eventaddr` 决定目的地：

| 模式 | 字节内容 | 默认值与兼容参数 |
| --- | --- | --- |
| `text --text-source=hook` | hook 事件文本 | 目的地为空时输出到 stdout |
| `text --text-source=pcapng` | 重组后的 HTTP/1.1 或 HTTP/2 消息 | 默认明文 stdout；可另存 `--pcapfile`、`--keylogfile` |
| `keylog` | NSS Key Log 文本行 | 归一化后必须有目的地；`--keylogfile` 是原有的主文件参数 |
| `pcap` / `pcapng` | 含 TLS Decryption Secrets Block 的 pcapng 数据包流 | 归一化后必须有目的地；`--pcapfile` 是原有的主文件参数 |

当前 CLI 为旧文件参数提供的默认文件名仍兼容。显式设置 `--eventaddr` 和对应的主文件参数会报错。
pcapng 模式中的 `--keylogfile` 则表示可选的额外密钥文件。
pcapng 文本源在内部使用数据包及 TLS 密钥重组 HTTP；暂不支持 HTTP/3 文本重组。

目的地支持 `stdout`、普通路径、`file://` 路径、`tcp://host:port`、
`ws://host:port/path` 和 `wss://host:port/path`。TCP 是有序字节流。
WebSocket 使用二进制消息，接收端按到达顺序拼接 payload 得到完整字节流，不能按 Protobuf 解码。
连接失败后流结束，不会在一个捕获文件中途自动重连。

轮转仅适用于文件型 text/keylog 输出，不适用于网络输出或 pcapng。
运行日志默认使用 stderr，因而 pcapng 的 stdout 只包含二进制数据；
显式组合 `--logaddr stdout` 与 pcapng `--eventaddr stdout` 会被拒绝。

在支持的 Linux/Android 主机上，以探针所需权限运行：

```bash
# 事件与运行日志分别存放。
sudo ./bin/ecapture tls --eventaddr=/tmp/events.txt --logaddr=/tmp/ecapture.log

# 原始 TCP 接收端须已启动。
sudo ./bin/ecapture tls -m keylog --eventaddr=tcp://127.0.0.1:9000

# stdout 写出含密钥的二进制 pcapng。
sudo ./bin/ecapture tls -m pcapng -i eth0 --eventaddr=stdout > /tmp/capture.pcapng
```

请按目标调整库/可执行文件路径、网卡与捕获过滤条件。keylog 和 pcapng 属于敏感产物。

## eCaptureQ 类型化事件

```bash
# 同时输出文件和类型化 WebSocket 消息。
sudo ./bin/ecapture tls --eventaddr=/tmp/events.txt \
  --ecaptureq=ws://127.0.0.1:28257/
```

内置监听器接受 `ws://`；原始输出支持 `wss://` 不代表该服务器提供 TLS。
尾部 `/` 是常用写法，CLI 解析器不强制要求。可以绑定 `0.0.0.0`，客户端应连接可访问的主机地址。
内置接口没有应用层认证，应据此选择监听范围。

每条二进制 WebSocket 消息包含一个 Protobuf `LogEntry`，按 `log_type` 和对应 payload 分发：

- `HEARTBEAT`：每个连接的健康消息，连接后立即发送，随后每 15 秒发送。
- `PROCESS_LOG`：eCapture 生命周期与运行日志。新客户端最多收到最近 128 条运行日志，随后接收实时日志。
- `EVENT`：捕获数据，携带格式、敏感性以及可用的进程/网络信息。只发送实时事件，不回放历史事件。

pcapng 格式的类型化事件描述单个数据包，不是 pcapng 文件片段；仅携带密钥的 DSB 记录不会变成数据包行。
pcapng 文本源重组出的 HTTP 事件使用 text 格式并标为敏感。
队列容量有限，慢客户端可能断开，发布端可能收到背压错误；该接口不提供持久化消息队列语义。

字段语义参见[协议参考](../protobuf/PROTOCOLS-zh_Hans.md)，构建、接收、解码和手工检查参见
[Go 客户端示例](../examples/ecaptureq_client/README.md)。其他语言可从
[ecaptureq.proto](../protobuf/proto/v1/ecaptureq.proto) 生成类型，逐条读取并解码二进制 WebSocket 消息。

另见[社区集成](event-forward.md)、[HTTP 配置更新](remote-config-update-api-zh_Hans.md)和
[输出架构](agent/output-pipeline.md)。
