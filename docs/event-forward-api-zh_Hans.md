# 输出与订阅 API

[English](event-forward-api.md)

TLS（OpenSSL/BoringSSL）、GoTLS、GnuTLS 共用三个启动入口：

| 参数 | 用途 | 默认值 |
| --- | --- | --- |
| 可重复的 `--output` | 向指定目的端写入运行日志和捕获事件 | `stdout` |
| `--stream-listen ws://HOST:PORT/PATH` | 监听客户端拉取 Protobuf v2 记录 | 关闭 |
| `--config-listen HOST:PORT` | 监听 HTTP 配置更新 | 关闭 |

显式 `--output` 替换默认 stdout；重复传参组成数组，不按逗号拆分。
`--listen`、`--eventaddr`、`--logaddr`、`-l`、`--ecaptureq` 和旧事件轮转参数直接删除，
没有别名或兼容层。`console`、主动连接的 WS/WSS、`listen+ws://` 都不是受支持的 output 值。
升级时须同时更新启动脚本与接收端解码。

## 目的端与模式

| 目的端 | 连接方向 | text | keylog / pcapng |
| --- | --- | --- | --- |
| `stdout` / `stderr` | 写终端 | 可读运行日志及文本事件 | 可读运行日志及原生事件表示 |
| 本地路径 / `file:///PATH` | 写本地文件 | JSON Lines：`PROCESS_LOG` 与 `EVENT` | JSON Lines：仅 `PROCESS_LOG` |
| `tcp://HOST:PORT` | 主动连接接收端 | JSON Lines：运行日志与 TEXT 事件 | JSON Lines：运行日志与 KEYLOG/PCAPNG 原生事件 |
| `--stream-listen ws://…` | 客户端连接 eCapture | Protobuf v2 二进制记录 | 含 KEYLOG/PCAPNG 原生字节的 Protobuf v2 |

每行终端文本包含 `log_type=log` 或 `log_type=event`、`module`；事件行另含
`capture_format`。pcapng 在终端表示为编码字节数摘要。JSON 和 Protobuf 共用 LogEntry，
以 `log_type` 区分日志/事件，再用 `event_payload.capture_format` 判断事件内容。
JSON 文件不等于 pcapng；原生文件必须单独指定。

| 捕获模式（`--model`、`-m`） | 原生文件要求 |
| --- | --- |
| `text --text-source pcapng` | `--pcapfile`、`--keylogfile` 可选；事件仍是 SDK 解码后的 TEXT |
| `keylog` | 必须显式指定 `--keylogfile PATH`，输出 NSS Key Log |
| `pcapng` | 必须显式指定 `--pcapfile PATH`，包含 TLS DSB；`--keylogfile` 可选 |

不再自动创建默认原生文件名。原生文件参数只能是本地文件，不能与 JSON output 使用同一文件，
也不接受 stdout、stderr、网络 URL。未指定网卡时自动选择，可通过 `-i` 覆盖；GoTLS 还需
`--elfpath` 指定目标程序。

```bash
# 终端与日志/事件合并 JSON 文件。
sudo ./bin/ecapture tls --model text --text-source pcapng \
  --output stdout --output /tmp/records.jsonl

# JSON TCP 接收端应提前监听。
sudo ./bin/ecapture gotls --model text --text-source pcapng \
  --elfpath /path/to/go-client --output tcp://127.0.0.1:9000

# 抓包文件与运行日志 JSON 文件相互独立。
sudo ./bin/ecapture tls --model pcapng -i eth0 --pcapfile /tmp/capture.pcapng \
  --output /tmp/runtime.jsonl --stream-listen ws://127.0.0.1:28257/

sudo ./bin/ecapture gnutls --model keylog --keylogfile /tmp/gnutls.keys \
  --output stderr --output tcp://127.0.0.1:9000
```

按目标 Linux/Android 主机选择库/程序路径、过滤条件和探针权限。
内置监听器提供 WS，不提供 TLS 或应用层认证，示例绑定 loopback；URL path 就是订阅路径。

## v2 接收处理

WebSocket 必须协商 `ecapture.v2`，每个二进制消息解码一个 LogEntry；JSON 接收端按完整换行
分割记录。参见[协议参考](../protobuf/PROTOCOLS-zh_Hans.md)和
[Go 示例](../examples/ecaptureq_client/README.md)。不支持 v1 负载。

PROCESS_LOG 进入运行日志，HEARTBEAT 用于连接健康检查，EVENT 按匹配的格式/oneof 处理。
TEXT 保留全部元数据；KEYLOG 的 `keylog.data` 和 PCAPNG 的 `pcapng.data` 在 ProtoJSON
解码后按顺序直接追加到原生文件。bytes 仅在 JSON 中使用 base64；消息可能切开原生行/block。
pcapng 包含真实编码器的头、包与密钥块，不是打印摘要的集合。

监听器保留最近最多 128 条运行日志，不保存事件历史。pcapng 晚连接从独立 session 的头部开始，
只获取未来包和密钥；不重放历史握手/密钥，已有 TLS 连接可能无法解密。
有界队列会断开慢客户端；没有持久交付或断点续传。

## generation 和完成判定

输出目的端属于进程级启动配置，HTTP 不允许修改。成功重载会结束旧 capture generation，
刷新编码器并排空连接后再开始新代。TCP 主动输出会关闭并重新连接原地址，WS 客户端自行重连。
即使模式未变，每条连接也应使用独立原生文件。

WS 只有成功排空后的 Close 1000 才代表传输正常结束；1011、直接 EOF、超时和接收端中断都应
保留 `.partial`。示例还会 flush/close 并校验文件结构后再转为正式文件。
TCP EOF 没有成功状态，没有可信外部完成信号时必须保留 `.partial`。
结构完整或正常 close 均不证明没有丢包或 TLS 一定可解密。

另见 [HTTP 配置更新](remote-config-update-api-zh_Hans.md)、
[社区集成](event-forward.md)及[输出架构](agent/output-pipeline.md)。
