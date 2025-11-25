## Issue Response Draft for Maintainer

> **Note**: This file contains a draft response for Issue #846. The maintainer can copy and post this to the issue, or edit as needed.

---

感谢您的反馈和问题！

### 问题理解

您希望在使用 `-m key/keylog` 模式获取 `client_random` 和 TLS 密钥信息的同时，也能获取到对应连接的五元组（源 IP、源端口、目标 IP、目标端口、协议）信息。

### 当前实现分析

目前 eCapture 在 `-m key/keylog` 模式下的设计是仅捕获 TLS 握手相关的密钥信息（client_random、master_key 等），**并不包含网络五元组信息**。

这是因为 keylog 模式使用 `uprobe` 钩住 SSL 相关函数（如 `SSL_get_wbio`、`SSL_do_handshake`、`SSL_in_before`），在这些钩子点上，SSL 上下文并不直接暴露底层 socket 的网络连接信息。

### 可选方案

#### 方案一：使用 `-m text` 模式（推荐）

如果您需要同时获取 TLS 明文**和**网络连接信息，建议使用 `-m text` 模式：

```bash
sudo ./ecapture tls -m text --pid=<目标进程PID>
```

Text 模式会：
- 钩住 `SSL_read`/`SSL_write` 捕获 TLS 明文数据
- 通过内核探针跟踪 `sys_connect`、`inet_stream_connect`、`inet_accept` 获取网络连接信息
- 通过 `SSL_set_fd` 系列函数关联 SSL 上下文与 socket fd

输出中会包含连接的 tuple 信息（如 `192.168.1.1:12345-10.0.0.1:443`）。

#### 方案二：使用 `-m pcap/pcapng` 模式

如果您需要密钥信息 + 完整的网络数据包：

```bash
sudo ./ecapture tls -m pcap -i <网卡名> -w output.pcapng --pid=<目标进程PID>
```

Pcap 模式会：
- 捕获 master secret 密钥信息
- 使用 TC (Traffic Control) 钩子捕获网络数据包
- 将密钥写入 pcapng 文件的 DSB (Decryption Secrets Block)，可直接用 Wireshark 解密

#### 方案三：功能增强请求（Feature Request）

如果您确实需要在 keylog 模式下获取五元组信息，这需要对当前实现进行增强，主要工作包括：

1. 在 keylog 模式中增加 `SSL_set_fd` 系列函数的钩子，建立 SSL 上下文到 fd 的映射
2. 增加内核探针跟踪 `sys_connect`/`inet_stream_connect`/`inet_accept` 获取 fd 对应的网络连接信息
3. 在 master secret 事件中关联对应的五元组信息

如果这是您的核心需求，欢迎：
- 在本 Issue 中详细描述您的使用场景，帮助我们评估优先级
- 或者参与贡献代码实现（可以参考 `probe_openssl_text.go` 中的连接跟踪实现）

### 补充信息请求

为了更好地理解您的需求，麻烦补充以下信息：

- 您的具体使用场景是什么？（例如：安全审计、流量分析、调试等）
- 您是需要实时关联还是事后分析？
- 您当前使用的操作系统和内核版本？

期待您的反馈！
