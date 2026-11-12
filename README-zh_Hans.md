<p align="center">
  <img src="./images/ecapture-logo.svg" alt="eCapture 标志" width="180" />
</p>

<p align="center">
  <strong>eCapture（旁观者）</strong><br />
  使用 eBPF 捕获 SSL/TLS 明文，无需中间人（MITM）代理或安装自定义 CA 证书。
</p>

<p align="center">
  <a href="./README.md">English</a> · <strong>汉字</strong><br />
  <a href="https://github.com/gojue/ecapture/actions/workflows/codeql-analysis.yml"><img alt="CodeQL" src="https://github.com/gojue/ecapture/actions/workflows/codeql-analysis.yml/badge.svg" /></a>
  <a href="https://github.com/gojue/ecapture/releases"><img alt="最新版本" src="https://img.shields.io/github/v/release/gojue/ecapture?display_name=tag&amp;include_prereleases&amp;sort=semver" /></a>
  <a href="https://ecapture.cc"><img alt="项目主页" src="https://img.shields.io/badge/项目主页-e0ad15" /></a>
  <a href="https://qm.qq.com/cgi-bin/qm/qr?k=iCu561fq4zdbHVdntQLFV0Xugrnf7Hpv&amp;jump_from=webapi&amp;authKey=YamGv189Cg+KFdQt1Qnsw6GZlpx8BYA+G2WZFezohY4M03V+l0eElZWOhZj/wR/5"><img alt="QQ 群" src="https://img.shields.io/badge/QQ群-%2312B7F5?logo=tencent-qq&amp;logoColor=white&amp;style=flat-square" /></a>
</p>

<p align="center">
  <a href="https://www.star-history.com/gojue/ecapture">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/badge?repo=gojue/ecapture&amp;type=rank&amp;theme=dark" />
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/badge?repo=gojue/ecapture&amp;type=rank" />
      <img alt="Star History 全球排名" src="https://api.star-history.com/badge?repo=gojue/ecapture&amp;type=rank" />
    </picture>
  </a>
  <a href="https://www.star-history.com/gojue/ecapture">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/badge?repo=gojue/ecapture&amp;type=trending&amp;theme=dark" />
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/badge?repo=gojue/ecapture&amp;type=trending" />
      <img alt="GitHub 当日热门仓库" src="https://api.star-history.com/badge?repo=gojue/ecapture&amp;type=trending" />
    </picture>
  </a>
</p>

> [!IMPORTANT]
> Linux 支持 x86_64（内核 4.18+）、aarch64（内核 5.5+）和 LoongArch64 `loong64`（内核 6.6+）。Android 继续支持 x86_64 和 aarch64，且最低内核要求不变。
> 需要 root 权限或特定的 [Linux capabilities](docs/minimum-privileges.md)。
> 不支持 Windows 和 macOS。

----

<!-- MarkdownTOC autolink="true" -->
- [简介](#简介)
- [快速上手](#快速上手)
  - [下载](#下载)
   - [ELF 可执行文件](#elf-可执行文件)
   - [Docker 镜像](#docker-镜像)
 - [快速体验](#快速体验)
  - [模块介绍](#模块介绍)
   - [OpenSSL 模块](#openssl-模块)
   - [GoTLS 模块](#gotls-模块)
    - [其他模块](#其他模块)
  - [使用演示](#使用演示)
- [星标成长曲线](#星标成长曲线)
- [安全与运维](#安全与运维)
- [贡献](#贡献)
- [二次开发](#二次开发)
- [微信公众号](#微信公众号)
<!-- /MarkdownTOC -->

----

# 简介

eCapture 的汉字名字为“旁观者”，寓意“当局者迷，旁观者清”，与其核心能力“旁路观察”相契合，同时也与英文名称在发音上有相似之处。

eCapture 使用 eBPF 的 `uprobe` / `Traffic Control` 等技术，在不修改目标程序的前提下，捕获用户空间和内核空间中的各类数据，适用于 TLS/SSL 明文抓取、命令审计和数据库查询审计等场景。

# 快速上手

## 下载

### ELF 可执行文件

> [!TIP]
> Linux 支持 x86_64、aarch64 和 LoongArch64；Android 支持 x86_64 和 aarch64。

可从 [Release](https://github.com/gojue/ecapture/releases) 页面下载对应的二进制包，解压后直接使用：

```shell
sudo ecapture --help
```

### Docker 镜像

> [!TIP]
> 仅支持 Linux。

```shell
# 拉取镜像
docker pull gojue/ecapture:latest

# 运行
docker run --rm --privileged=true --net=host -v ${HOST_PATH}:${CONTAINER_PATH} gojue/ecapture ARGS
```

> **⚠️ 安全提醒**：`--privileged=true` 会授予容器完整的宿主机访问权限。生产环境中，建议优先使用更细粒度的 Linux capabilities。详情请参阅 [最小权限指南](docs/minimum-privileges.md#method-3-docker-with-specific-capabilities)。

更多信息请参阅 [Docker Hub](https://hub.docker.com/r/gojue/ecapture)。

## 快速体验

运行 `ecapture --help`，查看当前安装版本支持的命令和参数。

下面以捕获基于 OpenSSL 动态链接库加密的网络通讯为例：

```shell
sudo ecapture tls
```

eCapture 会自动检测系统中的 OpenSSL 库并选择抓包网卡：优先选择 IPv4/IPv6 默认路由中 metric 最低的可用以太网网卡；没有可用默认路由时，参考网卡收发流量计数，再回退到已启用的网卡。启动时会通过 WARN 日志显示选中的网卡，并提示可通过 `-i eth0` 或 `--ifname eth0` 手动更改。只捕获选中网卡的流量；回环流量请指定 `-i lo`。使用链接 OpenSSL 的客户端发起 HTTPS 请求，即可看到重组后的请求和响应。下面是用于说明文本格式的合成 HTTP/1.1 示例：

```text
[2026-01-01T12:00:00.000000000Z] http/1.1 request 192.0.2.1:43210 -> 192.0.2.2:443 host="example.com" domain_source="Host" connection="17-4-client/192.0.2.1:43210--192.0.2.2:443/tcp#2"
GET / HTTP/1.1
Host: example.com

```

> 📄 输出格式和验证示例请参阅 [docs/example-outputs.md](docs/example-outputs.md)。

## 模块介绍

eCapture 包含 8 个模块，分别支持对 OpenSSL、GnuTLS、NSS/NSPR、BoringSSL 和 GoTLS 等 TLS/SSL 加密库的明文捕获，同时支持 Bash、MySQL 和 PostgreSQL 的审计与分析。

* bash：捕获 bash 命令行输入与执行内容
* zsh：捕获 zsh 命令行输入与执行内容
* gnutls：捕获基于 GnuTLS 加密通信的明文内容
* gotls：捕获 Go 语言程序中基于内置 TLS/HTTPS 实现的明文通信
* mysqld：捕获 MySQL 查询语句，支持 MySQL 5.6 / 5.7 / 8.0 及 MariaDB
* nss：捕获基于 NSS/NSPR 加密通信的明文内容
* postgres：捕获 PostgreSQL 10+ 的查询语句
* tls：捕获基于 OpenSSL/BoringSSL 的明文 TLS/SSL 流量，支持 OpenSSL 1.0.x / 1.1.x / 3.x 及更高版本，以及 BoringSSL 的所有发行版本

你可以通过 `ecapture -h` 查看各个子命令列表。

### OpenSSL 模块

eCapture 默认会读取 `/etc/ld.so.conf` 中的库加载目录并定位 `openssl` 等动态链接库的位置。你也可以通过 `--libssl` 参数显式指定动态库路径。

如果目标程序使用静态编译方式，则可以直接将 `--libssl` 参数设置为该程序的路径。

OpenSSL 模块支持三种输出模式：

- `pcap` / `pcapng`：将加密网络包和 TLS 密钥保存为 `pcap-NG` 格式。
- `keylog` / `key`：将 TLS 握手密钥保存到文件中。
- `text`：默认使用 `pcapng` 数据源，实时解密 pcapng 与 DSB，输出完整 HTTP/1.1 与 HTTP/2 请求和响应，自动选择抓包网卡，也可通过 `-i eth0` 手动指定。手动指定 `--text-source=hook` 可通过函数 hook 抓取明文，无需指定网卡。

对 OpenSSL、GoTLS 和 GnuTLS，`--eventaddr` 是统一的主事件目的端，支持
`stdout`、普通路径或 `file://` URI、`tcp://host:port` 以及使用有序二进制帧的
`ws://`/`wss://`。模式决定 text、NSS Key Log 或 pcapng 输出形式，地址只决定传输方式。
`--keylogfile` 和 `--pcapfile` 仍是相应模式的兼容文件别名；显式 `--eventaddr`
不能与对应的主别名同时使用。pcapng 模式下的 `--keylogfile` 仍是独立的可选密钥文件。

#### text 模式下实时解密

`tls`、`gotls` 和 `gnutls` 的 text 数据源均默认为 `pcapng`，省略 `-i` 时自动选择抓包网卡。
三个模块均可通过 `--text-source hook` 使用函数 hook；GoTLS 仍需 `--elfpath` 指定目标程序。

`tls`、`gotls`、`gnutls` 均可使用 `-m text --text-source=pcapng`。输出按完整 HTTP/1.1 或
HTTP/2 请求/响应划分，包含方向、时间、源和目标 IP/端口、连接标识及 HTTP/2
流标识。`host` 优先取 HTTP `Host`，其次取 HTTP/2 `:authority`；两者都没有时
使用服务器 IP，并标注 `domain_source="server_ip"`。明文写入 `--eventaddr`，
默认 stdout。默认不保存原始 pcapng 或独立密钥文件；需要时显式指定
`--pcapfile` 或 `--keylogfile`。

```shell
sudo ecapture tls -m text --text-source=pcapng -i eth0 --eventaddr /tmp/http.events 'tcp port 443'
sudo ecapture gotls -m text --text-source=pcapng --elfpath /path/to/go-client -i eth0 --pcapfile /tmp/raw.pcapng 'tcp port 443'
sudo ecapture gnutls -m text --text-source=pcapng --gnutls /path/to/libgnutls.so -i eth0 'tcp port 443'
```

DSB 密钥块即使晚于握手和数据包写入，也会被 SDK 用于回放解密。HTTP/3 over
QUIC v1/v2 已有 GoTLS 测试用例；实际支持取决于对应 TLS 后端能否提供所需密钥。
以下选项均要求 text 模式和 pcapng 数据源：

| 参数 | 输出或选择范围 |
| --- | --- |
| `--text-raw` | 经认证的 TLS/QUIC STREAM 字节及 QUIC DATAGRAM 消息 |
| `--text-http-events` | 增量 HTTP/1.x、HTTP/2、HTTP/3、SSE 和 HTTP/2 gRPC 事件 |
| `--text-max-decoded-body N` | 每条消息的 gzip 解压字节上限，须启用 HTTP events；默认零保留原编码 |
| `--text-protocol dot\|doh\|doq\|mqtt\|redis` | 显式选择应用解析；MQTT 3.1.1、定长 RESP2/RESP3 |
| `--text-tls-upgrade smtp\|imap\|pop3\|ldap\|postgres\|mysql\|connect\|https-connect` | 一次显式 STARTTLS/SSLRequest/CONNECT 协商；HTTPS CONNECT 支持一层内层 TLS |
| `--text-udp-protocol dtls` | DTLS 1.2 ECDHE-RSA AES-128/256-GCM 记录；UDP 默认仍为 QUIC |

结构化事件使用无损 hex 和 `metadata` JSON，保留头部、trailers、消息/流 ID、
early-data 状态和 TLS 层级，空载荷事件也会输出。流分块含 offset/结束标记；
DATAGRAM 保留消息边界，不附加不存在的流 offset。应用协议需显式选择，不自动按 ALPN 分发。
raw、HTTP events、显式应用解析三种模式互斥。HTTP reload 使用对应下划线 JSON 字段，
省略时恢复模块字段的零值默认值。邮件/数据库升级只处理 TLS 协商，无对应应用解析器时
使用 `--text-raw` 获取明文字节；gRPC 事件保留无 schema 的 Protobuf 字节。
诊断单独写入运营日志，不含明文或密钥。
ECH 需要当前探针尚未采集的 `ECH_SECRET`/`ECH_CONFIG`，仅升级类库不能实现实时 ECH 解密。
DTLS/DATAGRAM 支持也不等于 WebRTC、WebTransport 或 MASQUE 应用解析。
v1.4.0 对部分客户端零长度 CID 的 QUIC 回环抓包仍有连接路由失败；
维护的 DoQ/DATAGRAM 基线使用 8 字节客户端 CID。

若要独立验证明文确实来自 pcapng，在采集命令中加入 `--pcapfile /tmp/raw.pcapng`，
并发送带唯一请求路径或响应标记的请求。停止 eCapture 后，使用 Wireshark >= 4.4
仅预加载该抓包自身的 DSB，以处理晚到密钥，再对比 TLS stream 0：

```shell
keys=$(mktemp)
editcap --extract-secrets /tmp/raw.pcapng - >"$keys"
tshark -n -r /tmp/raw.pcapng -o "tls.keylog_file:$keys" -q -z follow,tls,ascii,0
rm -f -- "$keys"
```

可选文件与实时 SDK 输入接收的是同一份 pcapng 字节流。

`--logaddr` 只承载 eCapture 自身的运行日志。控制台运行日志输出到 stderr，而
事件 stdout 只包含捕获数据。eCaptureQ 是附加的 typed publisher，不会取代
`--eventaddr` 或 `--logaddr`。

#### Pcap 模式

支持基于 TCP 的 HTTP `1.0/1.1/2.0` 以及基于 UDP 的 HTTP/3 (`QUIC`) 流量抓取。

你可以通过 `-m pcap` 或 `-m pcapng` 参数指定抓包模式，并配合 `--pcapfile` 和 `-i` 参数使用。当前为了兼容保留的 `--pcapfile` 默认值为 `save.pcapng`。

```shell
sudo ecapture tls -m pcap -i eth0 --pcapfile=ecapture.pcapng tcp port 443
```

该命令会将捕获的网络数据包和 TLS 密钥保存为 pcapng 文件。Wireshark 使用文件内嵌的密钥解密受支持的 TLS 流量。

> 📄 完整的 pcapng 模式输出示例，请参阅 [docs/example-outputs.md](docs/example-outputs.md#tls-module--pcapng-mode)。

#### Keylog 模式

你可以通过 `-m keylog` 或 `-m key` 参数指定密钥导出模式，并配合 `--keylogfile` 参数使用，当前为了兼容保留的默认输出文件为 `ecapture_openssl_key.log`。

捕获到的 OpenSSL TLS `Master Secret` 信息会保存到 `--keylogfile` 中。你也可以同时开启 `tcpdump` 抓包，然后使用 Wireshark 打开对应 pcap 文件，并设置 `Master Secret` 路径，即可解密并查看明文数据包。

```shell
sudo ecapture tls -m keylog --keylogfile=openssl_keylog.log
```

也可以直接使用 `tshark` 进行实时解密和展示：

```shell
tshark -o tls.keylog_file:openssl_keylog.log -Y http -T fields -e http.file_data -f "port 443" -i eth0
```

#### Text 模式

```shell
sudo ecapture tls -m text
```

该命令使用默认的 `pcapng` 数据源重组 HTTP 消息。如需捕获 TLS 读写函数中的明文字节，可使用 `sudo ecapture tls -m text --text-source hook`，无需指定网卡。

### GoTLS 模块

该模块与 OpenSSL 模块的原理相似。

#### 启动方式

步骤 1：

```shell
sudo ecapture gotls --elfpath=/path/to/go-client
```

步骤 2：

```shell
/path/to/go-client
```

#### 更多帮助

```shell
sudo ecapture gotls -h
```

### 其他模块

eCapture 还支持其他模块，例如 `bash`、`mysqld`、`nss`、`postgres` 等，更多详细信息可通过 `ecapture -h` 查看。

## 使用演示

### 介绍文章

[eCapture：无需 CA 证书抓取 HTTPS 明文通讯](https://mp.weixin.qq.com/s/DvTClH3JmncpkaEfnTQsRg)

### 视频：Linux 上使用 eCapture

[![eCapture User Manual](./images/ecapture-user-manual.png)](https://www.bilibili.com/video/BV1si4y1Q74a "eCapture User Manual")

### 视频：Android 上使用 eCapture

[![eCapture User Manual](./images/ecapture-user-manual-on-android.png)](https://www.bilibili.com/video/BV1xP4y1Z7HB "eCapture for Android")

## eCaptureQ 图形界面程序

[eCaptureQ](https://github.com/gojue/ecaptureq) 是 eCapture 的跨平台图形界面客户端，用于可视化展示 eBPF TLS 抓包能力。它基于 Rust + Tauri + React 构建，提供实时响应式界面，无需 CA 证书即可轻松分析加密流量，降低了复杂 eBPF 抓包技术的使用门槛。

它支持两种模式：

* 集成模式：Linux/Android 一体化运行
* 远程模式：Windows/macOS/Linux 客户端连接远程 eCapture 服务

### 事件转发项目

[事件转发相关项目](./docs/event-forward.md)

### 视频演示

https://github.com/user-attachments/assets/c8b7a84d-58eb-4fdb-9843-f775c97bdbfb

🔗 [GitHub 仓库](https://github.com/gojue/ecaptureq)

### Protobuf 协议说明

有关 eCapture/eCaptureQ 使用的 Protobuf 日志格式说明，详见：

- [protobuf/PROTOCOLS-zh_Hans.md](protobuf/PROTOCOLS-zh_Hans.md)

## 星标成长曲线

<a href="https://www.star-history.com/?repos=gojue%2Fecapture&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=gojue/ecapture&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=gojue/ecapture&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=gojue/ecapture&type=date&legend=top-left" />
 </picture>
</a>

# 安全与运维

- [**安全策略**](SECURITY.md) — 漏洞报告流程与支持版本说明
- [**最小权限指南**](docs/minimum-privileges.md) — 所需的 Linux capabilities 与最小权限配置
- [**防御与检测**](docs/defense-detection.md) — 如何检测和防御未经授权的使用
- [**性能基准测试**](docs/performance-benchmarks.md) — 可重复的性能开销与事件丢失测量方法
- [**发布验证**](docs/release-verification.md) — 如何验证发布产物的完整性

# 贡献

请参考 [CONTRIBUTING](./CONTRIBUTING.md) 了解提交补丁、问题反馈和贡献流程，感谢您的支持与参与。

# 二次开发

## 自行编译

你可以按需定制功能，例如设置 `uprobe` 的偏移地址，以支持静态编译的 OpenSSL 库。编译方法可参考 [编译指南](docs/compilation-zh_Hans.md)。

Loong64 发布产物在 Ubuntu 24.04 x86_64 上使用 LLVM 22.1.8 交叉构建，入口为
`TARGET_ARCH=loong64`。sysroot、BTF、验收命令和当前运行时验证限制见
[Loong64 构建与验证](docs/loong64-support.md)。

## 动态修改配置

当 eCapture 运行后，你可以通过 HTTP 接口动态修改配置，详情请参考 [HTTP API 文档](docs/remote-config-update-api-zh_Hans.md)。

## 事件转发

eCapture 支持多种事件转发方式，你可以将事件转发到 Burp Suite 等抓包工具。详情请参考 [事件转发 API 文档](docs/event-forward-api-zh_Hans.md)。

# 微信公众号

![](./images/wechat_gzhh.png)
