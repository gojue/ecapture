# 运行时配置 HTTP API

[English](remote-config-update-api.md)

此 API 用新配置重启当前探针。启动 eCapture 时须显式启用；`--listen` 默认为空，即关闭：

```bash
sudo ./bin/ecapture tls --listen=127.0.0.1:28256 \
  --eventaddr=/tmp/events.txt
```

请求使用 `POST` 和 `Content-Type: application/json`。
内置 HTTP 服务器没有应用层认证或 TLS，示例绑定回环地址。
此接口与 `--ecaptureq` 事件监听器相互独立。

## 范围与路由

只向进程启动时选择的**同一探针类型**提交配置。
例如，用 `tls` 启动的进程通过 `/tls`、`/openssl` 或 `/boringssl` 更新 TLS 配置。
运行时始终保留原来的 factory probe type，不支持跨探针热切换。
向其他探针路由提交配置不是切换模块的方法，可能在重新初始化时失败。

| POST 路径 | 配置类型 | Linux | Android 构建 |
| --- | --- | --- | --- |
| `/tls`、`/openssl`、`/boringssl` | OpenSSL/BoringSSL | 支持 | 支持 |
| `/gotls` | GoTLS | 支持 | 支持 |
| `/bash` | Bash | 支持 | 支持 |
| `/gnutls` | GnuTLS | 支持 | 不支持 |
| `/nss`、`/nspr` | NSPR/NSS | 支持 | 不支持 |
| `/mysqld` | MySQL | 支持 | 不支持 |
| `/postgres`、`/postgress` | PostgreSQL | 支持 | 不支持 |

两种构建都会注册这些路由。Android 不支持的配置工厂返回 HTTP 400、`code: 4`，并非路由不存在。
当前没有 `/zsh` 路由，`/postgress` 保留为兼容别名。
平台支持不代表目标库/可执行文件无需满足各探针的要求。

## 配置替换与继承

服务器将请求解码到**新建的模块配置**中，再校验和应用，并非对运行中的配置执行通用 JSON patch。
只有下列三个字段在省略时继承当前实例的值：

| JSON 字段 | 含义 | 显式值 |
| --- | --- | --- |
| `event_collector_addr` | 主捕获事件目的地 | `""` 在模式归一化前显式清空目的地 |
| `event_rotate_size_mb` | 文件轮转大小 | `0` 关闭此大小阈值 |
| `event_rotate_seconds` | 文件轮转间隔 | `0` 关闭此时间阈值 |

其他省略的公共字段和模块字段使用构造函数默认值或零值，不继承当前值。
请重新提供需要保留的库/ELF 路径、模式、过滤器等设置。CLI 参数名不等于 JSON 字段名。
当前解码器通常忽略未知 JSON 字段，拼写错误可能使配置静默保留默认值。

空事件目的地在 text 模式下归一化为 stdout；keylog/pcapng 归一化后仍须有目的地，
可以由旧文件字段提供。轮转只支持文件型 text/keylog 输出。
从轮转文件切到网络目的地时，应显式将两个轮转字段设为零，避免继承不适用的配置。

运行日志和类型化 eCaptureQ 发布器是进程级依赖，会重新绑定到新探针。
此 API 不会更改 `--logaddr`、`--ecaptureq` 或 HTTP 监听地址。

## 请求字段

公共字段以 [BaseConfig](../internal/config/base_config.go) 和
[CommonConfigPatch](../internal/config/common.go) 为准：

| JSON 字段 | 类型 | 说明 |
| --- | --- | --- |
| `pid`、`uid` | 无符号整数 | 进程/用户过滤，`0` 表示不按该项过滤 |
| `debug`、`is_hex` | 布尔 | 探针调试与十六进制表示设置 |
| `btf_mode` | 无符号整数 | `0` 自动、`1` CO-RE、`2` non-CO-RE；须由内嵌资产支持 |
| `per_cpu_map_size` | 整数 | 正数，单位为**字节**；CLI `--mapsize` 的单位为页 |
| `event_collector_addr` | 字符串 | stdout、文件/路径、TCP 或 WebSocket 目的地 |
| `event_rotate_size_mb`、`event_rotate_seconds` | 无符号 16 位整数 | 文件轮转设置 |
| `cgroup_path` | 字符串 | 支持该能力的探针使用的 cgroup 过滤 |
| `perf_reorder`、`perf_reorder_lag_ms` | 布尔、无符号整数 | 支持该能力的探针/读取器使用的事件重排设置 |

`byte_code_file_mode` 必须匹配二进制内嵌资产模式，通常保留配置工厂默认值。
`truncate_size` 虽被序列化，当前生产路径没有消费方，不应依赖它限制输出。

常用模块字段：

| 探针 | JSON 字段名 | 定义 |
| --- | --- | --- |
| OpenSSL/BoringSSL | `opensslpath`、`capturemode`、`text_source`、`keylogfile`、`pcapfile`、`ifname`、`pcapfilter` | [config.go](../internal/probe/openssl/config.go) |
| GoTLS | `elf_path`、`capture_mode`、`text_source`、`keylog_file`、`pcap_file`、`ifname`、`pcap_filter` | [config.go](../internal/probe/gotls/config.go) |
| GnuTLS | `gnutlspath`、`capturemode`、`text_source`、`keylogfile`、`pcapfile`、`ifname`、`pcapfilter` | [config.go](../internal/probe/gnutls/config.go) |
| NSPR/NSS | `nss_path`、`nspr_path` | [config.go](../internal/probe/nspr/config.go) |
| Bash | `bashpath`、`readline`、`errno` | [config.go](../internal/probe/bash/config.go) |
| MySQL | `MysqlPath`、`FuncName`、`Offset` | [config.go](../internal/probe/mysql/config.go) |
| PostgreSQL | `PostgresPath`、`FuncName`、`Offset` | [config.go](../internal/probe/postgres/config.go) |

MySQL/PostgreSQL 的模块字段目前没有显式 JSON tag，因此使用 Go 导出字段名。
TLS 模式接受 `text`、`keylog`、`pcap`/`pcapng`；text 模式下的 `text_source` 可选 `hook` 或 `pcapng`。
OpenSSL/BoringSSL、GoTLS 和 GnuTLS 的 text 模式在该字段省略或为空时均默认使用 `pcapng`。`ifname` 省略或为空时，
优先选择默认路由对应的可用以太网网卡，再参考流量计数或选择已启用的网卡。
启动警告会显示所选网卡；显式设置 `ifname` 可覆盖自动选择。
使用函数 hook 抓取时应显式设置 `"text_source":"hook"`。
数据包捕获及 pcapng 文本源需要网卡。模式与目的地的关系见[事件输出说明](event-forward-api-zh_Hans.md)。

## 调用示例

请将示例路径和过滤条件改为捕获主机上的实际值。
下面更新正在运行的 TLS 探针，并继承当前事件目的地及轮转设置：

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/tls \
  -H 'Content-Type: application/json' \
  --data '{"opensslpath":"/usr/lib/x86_64-linux-gnu/libssl.so.3","capturemode":"text","text_source":"hook","pid":1234}'
```

将目的地替换为已经启动的 TCP 接收端：

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/tls \
  -H 'Content-Type: application/json' \
  --data '{"opensslpath":"/usr/lib/x86_64-linux-gnu/libssl.so.3","capturemode":"text","pid":1234,"event_collector_addr":"tcp://127.0.0.1:9000","event_rotate_size_mb":0,"event_rotate_seconds":0}'
```

对于最初用 `gotls` 启动的进程，使用对应字段名并重新提供 ELF 路径：

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/gotls \
  -H 'Content-Type: application/json' \
  --data '{"elf_path":"/absolute/path/to/go-app","capture_mode":"text","text_source":"hook","pid":1234}'
```

## 响应与失败行为

```json
{"code":0,"module_type":"openssl","msg":"RespOK","data":null}
```

| HTTP 状态 | `code` | 含义 |
| --- | --- | --- |
| 200 | 0（`RespOK`） | 新探针实例已成功启动 |
| 400 | 4（`RespConfigDecodeFailed`） | JSON 为空/格式错误、类型不匹配或平台配置工厂不可用 |
| 400 | 5（`RespConfigCheckFailed`） | 运行时校验或实例切换失败，详情见 `msg` |
| 503 | 6（`RespSendToChanFailed`） | 更新队列无法接受请求，可退避后重试 |

未知路径和错误 HTTP 方法使用路由器的 404/405 响应，不一定包含上述 JSON。
意外的处理器错误可能返回 500。
`module_type` 是解码后的配置类型（`openssl`、`gotls`、`gnutls`、`nspr`、
`bash`、`mysql`、`postgres`），不代表跨探针切换成功。

校验失败时当前实例继续运行。校验通过后，先停止旧实例再启动新实例，期间可能存在捕获空档。
新实例启动失败时，运行时会尝试用旧配置重新启动；恢复或关闭失败可能终止捕获，
不能将 HTTP 400 一概解释为旧探针仍然健康运行。

成功响应在启动完成后发送，不是在排队后立即发送。
客户端超时或断开也不代表已入队的更新被取消。
调用方应保存完整的目标配置和最后可用配置，在结果不明确时检查运行日志，并避免密集并发更新。
