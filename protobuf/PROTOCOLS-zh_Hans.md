# eCaptureQ 传输协议

[English](PROTOCOLS.md) · [代码生成](README-zh_Hans.md)

协议以 [proto/v1/ecaptureq.proto](proto/v1/ecaptureq.proto) 为准，包名为 `event`。
Go 导入路径为 `pb "github.com/gojue/ecapture/v2/protobuf/gen/v1"`。
此协议用于 `--ecaptureq`，不用于 `--eventaddr` 原始字节流。

## 消息边界与枚举

每条二进制 WebSocket 消息是一个编码后的 `LogEntry`。
根据 `log_type` 分发，并检查对应的 `oneof payload` 成员：

| `LogType` | 值 | payload 字段（编号） | 含义 |
| --- | --- | --- | --- |
| `LOG_TYPE_HEARTBEAT` | 0 | `heartbeat_payload`（3） | 连接健康信息 |
| `LOG_TYPE_PROCESS_LOG` | 1 | `run_log`（4） | 运行日志字符串 |
| `LOG_TYPE_EVENT` | 2 | `event_payload`（2） | 捕获事件 |

`LogEntry.log_type` 的字段编号是 1，各 payload 成员互斥。
不要把未来新增的未知枚举值直接当作捕获事件处理。

| 枚举 | 取值 |
| --- | --- |
| `CaptureFormat` | `UNSPECIFIED=0`、`TEXT=1`、`KEYLOG=2`、`PCAPNG=3`，完整名称前缀为 `CAPTURE_FORMAT_` |
| `Sensitivity` | `NORMAL=0`、`SENSITIVE=1`，完整名称前缀为 `SENSITIVITY_` |

## Event

| 编号 | 字段 | Protobuf 类型 | 当前发布端语义 |
| --- | --- | --- | --- |
| 1 | `timestamp` | `int64` | Unix 秒 |
| 2 | `uuid` | `string` | 模块提供的关联标识，不保证每条消息全局唯一 |
| 3 | `src_ip` | `string` | 可用的源 IP |
| 4 | `src_port` | `uint32` | 可用的源端口 |
| 5 | `dst_ip` | `string` | 可用的目标 IP |
| 6 | `dst_port` | `uint32` | 可用的目标端口 |
| 7 | `pid` | `int64` | 可用的进程 ID |
| 8 | `pname` | `string` | 可用的进程名 |
| 9 | `type` | `uint32` | 下述内部领域事件类别 |
| 10 | `length` | `uint32` | 本条 `payload` 的字节数 |
| 11 | `payload` | `bytes` | 捕获内容，具体表示取决于事件格式 |
| 12 | `capture_format` | `CaptureFormat` | 文本、密钥或数据包表示 |
| 13 | `sensitivity` | `Sensitivity` | keylog、数据包、重组 HTTP 等敏感内容的分类 |
| 14 | `direction` | `string` | 生产者提供的方向；hook 事件使用 `read`/`write`，可能为空 |
| 15 | `original_length` | `uint32` | 可用时为原始负载/数据包长度，否则退回 payload 长度 |
| 16 | `stream_id` | `string` | 可选的生产者流标识 |
| 17 | `sequence` | `uint64` | 生产者局部顺序，不是全局或持久化序号 |

`type` 当前对应 `internal/domain.EventType`：`0=Output`、`1=ModuleData`、
`2=Processor`，**不是** HTTP/1、HTTP/2 请求/响应枚举。
模块私有记录可能在发布前已被消费，因此枚举中存在某个值不代表客户端一定能收到它。

元数据是否可用取决于探针和模式，客户端须接受零值和空值。
探针重载后 sequence 可能重新开始，不能只凭 UUID 假定消息唯一。

hook 文本事件的 payload 可以是捕获字节，也可以是模块的文本表示。
keylog 事件携带密钥材料。pcapng 格式事件携带数据包负载，不是完整 pcapng 块或文件；
仅用于 DSB 的密钥事件不会作为数据包行发送。
pcapng 文本源重组出的 HTTP 消息使用 `TEXT` + `SENSITIVE`。
详见[输出行为](../docs/event-forward-api-zh_Hans.md)。

字段 12–17 是既有 v1 消息的扩展；旧 Protobuf 客户端会忽略未知字段。
接收旧发布端数据时，应接受这些字段的零值/默认值。
`is_binary`、`payload_utf8` 等 UI 派生字段不属于协议。

## 心跳与交付行为

`Heartbeat` 包含 `int64 timestamp=1`（Unix 秒）、`int64 count=2`、
`string message=3`。当前服务器在连接后立即发送心跳，此后每 15 秒发送。
`count` 在每个连接中从零开始，是心跳计数，不是已交付事件数。

新客户端最多收到最近 128 条 `PROCESS_LOG`，随后接收实时日志；
捕获 `EVENT` 不保留历史回放。心跳可能与历史日志交错发送。
队列有容量限制，可能报告背压并断开慢客户端；不提供持久化交付或断点续传协议。

完整接收/解码实现见 [Go 客户端示例](../examples/ecaptureq_client/README.md)。
按 `log_type` 和匹配的 payload 处理，不要将所有消息直接解码为 `Event`。
