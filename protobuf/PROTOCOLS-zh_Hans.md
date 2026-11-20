# eCapture Protobuf v2 与 JSON Lines

[English](PROTOCOLS.md) · [代码生成](README-zh_Hans.md)

权威 schema 为 [proto/v2/ecaptureq.proto](proto/v2/ecaptureq.proto)，namespace 是
`ecapture.v2`。Go 导入 `pb "github.com/gojue/ecapture/v2/protobuf/gen/v2"`。
运行时仅输出 v2；这是不兼容的 wire format 变更，接收端须同时升级消息解码、事件分流和
原生文件处理。不能使用 v1 生成代码解码 v2。

## 传输和消息边界

- `--stream-listen ws://HOST:PORT/PATH` 监听客户端连接，握手必须携带并协商
  `Sec-WebSocket-Protocol: ecapture.v2`。每个二进制 WebSocket 消息恰好包含一个 `LogEntry`。
  非浏览器客户端也须提供有效 `Origin` 请求头，接收端示例已设置。
- `--output tcp://HOST:PORT` 主动连接接收端，每行是一个 ProtoJSON `LogEntry`。
  TCP read 不等于消息边界，接收端须缓冲到换行符。
- `--output FILE`、`--output file:///PATH` 使用相同的 JSON Lines 编码。
  text 模式包含运行日志和事件；keylog/pcapng 模式仅写运行日志，原生文件分别通过
  `--keylogfile`/`--pcapfile` 指定。
- `--output stdout`、`stderr` 输出带 `log_type`、`module` 字段的可读终端文本，
  不是 JSON 或原生文件字节。

ProtoJSON 使用 schema 的 snake_case 字段名和枚举名称。bytes 字段为 base64，
64 位整数为 JSON 字符串；应使用 Protobuf JSON 解码器，bytes 只解码一次，并保留整数精度。
默认值字段可以省略。终端前缀不属于任何原生文件格式。

## LogEntry 与校验

| 字段 | 编号 | 含义 |
| --- | --- | --- |
| `log_type` | 1 | `HEARTBEAT=0`、`PROCESS_LOG=1`、`EVENT=2`，名称前缀为 `LOG_TYPE_` |
| `event_payload` | 2 | `oneof payload` 中的事件 |
| `heartbeat_payload` | 3 | `oneof payload` 中的心跳 |
| `run_log` | 4 | `oneof payload` 中的运行日志字符串 |
| `module` | 5 | `tls`、`gotls`、`gnutls` 等规范模块名；未知时为空 |

按 `log_type` 分流，并检查匹配的 oneof 成员。缺少消息体、枚举与 oneof 不匹配、未知格式
均应拒绝，不能通过 payload 猜测。module 为开放名称，遇到新名称时应保留。
Go [校验辅助包](v2/validate.go) 提供一致的校验规则。运行日志和心跳不得混入原生文件。

`Heartbeat` 包含 Unix 秒 `timestamp=1`、`count=2` 和 `message=3`。
连接后立即发送，随后每 15 秒一次；count 从每条连接的零开始，不代表事件数。
新连接最多收到最近 128 条运行日志。捕获事件、数据包和密钥不缓存重放。
队列有界，慢客户端可能被断开；协议没有持久确认、历史游标或断点续传。

## Event 内容

`Event.capture_format=1` 必须与一个且仅一个 content 成员一致：

| CaptureFormat | 值 | oneof 成员 | 内容 |
| --- | --- | --- | --- |
| `CAPTURE_FORMAT_UNSPECIFIED` | 0 | 无 | 发布事件禁止使用 |
| `CAPTURE_FORMAT_TEXT` | 1 | `text=2` | 文本载荷及捕获元数据 |
| `CAPTURE_FORMAT_KEYLOG` | 2 | `keylog=3` | `KeylogEvent.data=1`：NSS Key Log 原生字节 |
| `CAPTURE_FORMAT_PCAPNG` | 3 | `pcapng=4` | `PcapngEvent.data=1`：pcapng 原生字节流 |

`--model text --text-source pcapng` 的解密结果仍是 TEXT。
KEYLOG 来自完成密钥派生、NSS 编码和去重后的输出，不是打印摘要。
PCAPNG 是编码器输出，包括 Section Header、Interface Description、Enhanced Packet、
Decryption Secrets Blocks 及包注释，不是裸包 payload。

同一连接和格式的 `data` 按到达顺序直接拼接。单条消息可能切开 keylog 行或 pcapng block；
不得插入长度、文本标签、JSON 或 Protobuf 外壳，也不要再次 base64 编码。
原生事件不伪造 TextEvent 的进程/网络元数据；pcapng 的可用包元数据应从 block 注释解析。
原生数据和 TEXT 的 argv/payload 都可能包含敏感信息。

## TextEvent

| 编号 | 字段 | 类型 | 语义 |
| --- | --- | --- | --- |
| 1 | `timestamp` | int64 | Unix 秒 |
| 2 | `uuid` | string | 生产者关联标识，不保证单条消息全局唯一 |
| 3–6 | `src_ip`、`src_port`、`dst_ip`、`dst_port` | string/uint32 | 可用的网络四元组 |
| 7–8 | `pid`、`pname` | int64/string | 可用的内核进程身份 |
| 9 | `type` | uint32 | 领域分类：0 Output、1 ModuleData、2 Processor |
| 10 | `length` | uint32 | `payload` 的实际字节数 |
| 11 | `payload` | bytes | 捕获文本或解码表示，可为二进制或空 |
| 12 | reserved | — | 旧 capture-format 位置，禁止复用 |
| 13 | `sensitivity` | enum | `SENSITIVITY_NORMAL=0`、`SENSITIVITY_SENSITIVE=1` |
| 14 | `direction` | string | 生产者已知的方向 |
| 15 | `original_length` | uint32 | 文本格式化前的原始捕获/SDK 字节长度，或回退为 payload 长度 |
| 16 | `stream_id` | string | 可选流标识 |
| 17 | `sequence` | uint64 | 生产者局部序号，不是全局顺序 |
| 18 | `process_args` | bytes | 捕获时以 NUL 分隔的 argv 快照，最多 256 字节 |
| 19 | `process_args_truncated` | bool | 快照触及上限，可能截在参数中间 |
| 20 | `tls` | map<string,string> | 可选、不含密钥的握手观测 |

不要丢弃 payload 为空的元数据事件。转发时应保留全部元数据、原始 bytes，尤其是方向、
原始长度、流 ID、序号、敏感性、argv 和 TLS。type 不是 HTTP 请求/响应枚举。
空值/零值表示未知；UUID 可能重复，重载后序号可能重置。SDK 重建 HTTP 使用 TEXT + SENSITIVE。
文本前缀或 hex 展示会使 `length` 大于 `original_length`，后者不是格式化 payload 的上限。
仅要求 `length == len(payload)`，不要为匹配展示结果而覆盖原始捕获长度。

argv 可以不是 UTF-8，也可能被进程改写，不能保证等于原始 exec 命令。
完整快照以 NUL 结束；被截断的快照为 256 字节。argv 不得进入运行日志。

TLS map 包括 `version`、`cipher_suite`、`cipher_suite_id`、`server_name`、`offered_alpn`、
`alpn`、`key_exchange_group`、`signature_algorithm`、`ja3`、`ja3_raw`、`ja4`、
`client_hello`（`initial_wire` / `initial_outer`）。未知字段省略；客户端指纹来自首个线上
ClientHello，协商结果来自服务端握手观测，不包含 TLS 密钥，也不承诺证书校验成功。

## 会话、重载及文件完整性

一条连接对应一个 capture generation。重载先排空旧代，再关闭其 TCP/WS 连接；
重新连接进入新的会话。每条连接使用独立原生文件，禁止把重连数据追加到旧文件。

pcapng 晚连接客户端获得独立编码器，从新的 Section/Interface Header 开始，仅包含未来的
包和密钥。历史握手包和密钥不重放，因此原有 TLS 连接可能无法解密；不能宣称该片段等同于
从进程启动时记录的完整本地文件。

正常 WS generation 先刷新编码器、排空队列再发送 Close 1000；异常发送 1011 或断开。
接收端先写 `.partial`，只有确认 Close 1000，并完成本地 flush/close/格式校验后才能转为正式文件。
EOF、超时、接收端被杀、非法消息或 Close 1006 都不代表完成。TCP 没有应用层完成标记，
即使 EOF 恰好落在 block 边界也不证明成功；没有可信的外部成功信号时仍应保留 `.partial`。
格式完整不等于没有丢包或 TLS 一定可解密。

[Go 接收端示例](../examples/ecaptureq_client/README.md) 展示了 v2 校验、保留元数据的 TEXT
展示及原生文件保存。另见[输出行为](../docs/event-forward-api-zh_Hans.md)和
[HTTP 重载](../docs/remote-config-update-api-zh_Hans.md)。
