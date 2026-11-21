# 运行时配置 HTTP API

[English](remote-config-update-api.md)

通过 `--config-listen` 显式启用配置更新服务，默认关闭。它使用校验后的替换配置重启当前探针，
与 Protobuf `--stream-listen` 服务独立。内置服务不提供 TLS 或应用层认证，示例绑定 loopback。

```bash
sudo ./bin/ecapture tls --model text --text-source pcapng \
  --config-listen 127.0.0.1:28256 --output stdout --output /tmp/records.jsonl
```

使用 `POST` 和 `Content-Type: application/json`。旧 `--listen` 和输出 CLI 参数已移除，
不存在兼容别名。

## 核心模块端点

请求必须对应启动时选定的探针。运行时保留原 factory probe type，不支持 TLS、GoTLS、GnuTLS
之间的跨模块热切换。

| POST 路径 | 配置 | 支持平台 |
| --- | --- | --- |
| `/tls`、`/openssl`、`/boringssl` | OpenSSL/BoringSSL | Linux、Android |
| `/gotls` | GoTLS | Linux、Android |
| `/gnutls` | GnuTLS | Linux；Android factory 返回 HTTP 400 |

## 配置替换与输出生命周期

服务先构造全新的模块配置并解码、校验，再应用；不是对现有配置做通用 JSON patch。
省略的普通字段使用 factory 默认值或零值，应重新提供需保留的库/ELF 路径、模式、过滤条件和选项。
核心模块在 text 模式下省略或清空 `text_source` 时默认使用 `pcapng`。抓包时省略 `ifname` 会自动选择网卡。

`--output`、`--stream-listen`、`--config-listen` 是进程级启动设置，通过运行时依赖跨重载保留，
HTTP 不允许修改。请求包含新输出路由字段或旧字段时会被拒绝，包括显式 `null`，
不会静默忽略或继承。包括 `output`、`outputs`、`stream_listen`、`config_listen`、
`eventaddr`、`event_collector_addr`、`logaddr`、`logger_addr`、`ecaptureq`、`listen`、
`event_rotate_size_mb`、`event_rotate_seconds` 等。

原生 `pcapfile`/`keylogfile` 仍属于各代模块配置。切到 keylog 必须显式提供 keylog 文件，
切到 pcapng 必须显式提供 pcap 文件。要单独保存新一代的采集结果，可使用新文件名。
text 模式使用 `pcapng` 数据源时，两种文件均可选。
原生目的端只能是本地文件，且与 JSON output 不同。其他未知 JSON 字段仍可能被忽略，
不要假设任意拼写都会被校验。

重载排空并关闭旧代的 TCP/WS 输出连接；TCP 按启动目的端重新连接，WS 客户端自行重连。
每条连接对应独立原生文件；pcapng 晚连接从新头部和未来包/密钥开始，不回放历史。
详见[输出及完成判定](event-forward-api-zh_Hans.md)。

## 请求字段

公共字段见 [BaseConfig](../internal/config/base_config.go) 与
[CommonConfig](../internal/config/common.go)：

| JSON 字段 | 类型 | 含义 |
| --- | --- | --- |
| `pid`、`uid` | 无符号整数 | 进程/用户过滤，0 不过滤 |
| `debug`、`is_hex` | boolean | 调试及文本展示选项 |
| `btf_mode` | 无符号整数 | 0 auto、1 CO-RE、2 non-CO-RE，须有对应内嵌资产 |
| `per_cpu_map_size` | 整数 | 正数，单位字节；CLI `--mapsize` 单位页 |
| `cgroup_path` | string | 模块支持时启用 cgroup 过滤 |
| `perf_reorder`、`perf_reorder_lag_ms` | boolean、无符号整数 | reader 支持的重排选项 |

`byte_code_file_mode` 通常保留 factory 默认值，必须与内嵌资产一致。
`truncate_size` 当前没有生产消费者。

| 模块 | 字段 | 定义 |
| --- | --- | --- |
| TLS | `opensslpath`、`capturemode`、`text_source`、`keylogfile`、`pcapfile`、`ifname`、`pcapfilter` | [config.go](../internal/probe/openssl/config.go) |
| GoTLS | `elf_path`、`capture_mode`、`text_source`、`keylog_file`、`pcap_file`、`ifname`、`pcap_filter` | [config.go](../internal/probe/gotls/config.go) |
| GnuTLS | `gnutlspath`、`capturemode`、`text_source`、`keylogfile`、`pcapfile`、`ifname`、`pcapfilter` | [config.go](../internal/probe/gnutls/config.go) |

模式为 `text`、`keylog`、`pcapng`（模式值仍接受 `key`/`pcap`）。核心集成使用
`text_source: "pcapng"`。自动网卡优先可用默认路由 Ethernet 接口，再按流量计数或 up 接口
选择；启动日志说明结果，可通过 `ifname` 指定。明文 hook 逐步弃用期间仍保留 `text_source: "hook"`。

## 示例

保留启动时的输出目的端，替换 TLS 捕获配置：

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/tls \
  -H 'Content-Type: application/json' \
  --data '{"opensslpath":"/usr/lib/x86_64-linux-gnu/libssl.so.3","capturemode":"text","text_source":"pcapng","ifname":"eth0","pid":1234}'
```

对以 gotls 启动的进程，使用 GoTLS 字段名并重新提供 ELF 路径：

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/gotls \
  -H 'Content-Type: application/json' \
  --data '{"elf_path":"/absolute/path/to/go-app","capture_mode":"pcapng","pcap_file":"/tmp/generation-2.pcapng","ifname":"eth0","pid":1234}'
```

修改输出目的端需要用新 CLI 参数重启进程；提交 `{"output":["tcp://127.0.0.1:9000"]}` 会被拒绝。

## 响应与失败语义

```json
{"code":0,"module_type":"openssl","msg":"RespOK","data":null}
```

| HTTP | code | 含义 |
| --- | --- | --- |
| 200 | 0 (`RespOK`) | 新代已成功启动 |
| 400 | 4 (`RespConfigDecodeFailed`) | 空/非法 JSON、类型错误、禁用路由字段或平台 factory 不可用 |
| 400 | 5 (`RespConfigCheckFailed`) | 校验或 generation 切换失败，参见 msg |
| 503 | 6 (`RespSendToChanFailed`) | 更新队列已满，应退避重试 |

路由器 404/405 和未预期的 500 可能使用不同响应格式。module_type 是配置类型，不代表完成
跨模块切换。校验失败会保留当前探针；校验通过后先停旧代再启新代，存在捕获间隙。
新代启动失败会尝试恢复旧配置，回滚或关闭失败可能终止进程；HTTP 400 本身不保证旧探针仍正常。

成功响应在启动完成后返回，而非仅入队。客户端超时或断开不代表已经取消更新。
保留目标配置与上一份可用配置，结果不确定时检查运行日志，并避免并发重载。
