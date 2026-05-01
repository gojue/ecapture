# TLS/SSL 明文捕获（OpenSSL / BoringSSL）

## 概述

`tls` 模块是 eCapture 最核心的探针，通过 eBPF uprobe 挂钩 OpenSSL/BoringSSL 的 `SSL_read`、`SSL_write`、`SSL_do_handshake` 等函数，在数据加密之前（发送）或解密之后（接收）读取明文内容。

## 支持的库版本

### OpenSSL

eCapture 为每个 OpenSSL 版本维护专门的 eBPF 内核程序（因为不同版本的内部结构体偏移量不同）：

| 版本范围 | eBPF 字节码文件 |
|---------|----------------|
| 1.0.2a+ | `openssl_1_0_2a_kern.c` |
| 1.1.0a+ | `openssl_1_1_0a_kern.c` |
| 1.1.1a ~ 1.1.1j | `openssl_1_1_1a/b/d/j_kern.c` |
| 3.0.0 ~ 3.0.12 | `openssl_3_0_0/12_kern.c` |
| 3.1.0 | `openssl_3_1_0_kern.c` |
| 3.2.0 ~ 3.2.4 | `openssl_3_2_0/3/4_kern.c` |
| 3.3.0 ~ 3.3.2 | `openssl_3_3_0/2_kern.c` |
| 3.4.0 ~ 3.4.1 | `openssl_3_4_0/1_kern.c` |

### BoringSSL

BoringSSL 按 Android 版本分支维护：

| 分支 | 说明 | eBPF 字节码 |
|------|------|------------|
| `a_13` | Android 13 | `boringssl_a_13_kern.c` |
| `a_14` | Android 14 | `boringssl_a_14_kern.c` |
| `a_15` | Android 15 | `boringssl_a_15_kern.c` |
| `a_16` | Android 16 | `boringssl_a_16_kern.c` |
| `na` | 非 Android BoringSSL | `boringssl_na_kern.c` |

## 库路径自动发现

eCapture 默认通过以下方式自动查找 OpenSSL 库位置：

1. 读取 `/etc/ld.so.conf` 获取动态链接库搜索路径
2. 在搜索路径中查找 `libssl.so`
3. 自动检测 OpenSSL 版本，选择对应的 eBPF 字节码

手动指定库路径：

```bash
sudo ecapture tls --libssl=/lib/x86_64-linux-gnu/libssl.so.3
```

## 三种输出模式

### Text 模式（默认）

```bash
sudo ecapture tls -m text
```

直接输出明文内容，适合快速调试和实时监控。

### PcapNG 模式

```bash
sudo ecapture tls -m pcap -i eth0 --pcapfile=ecapture.pcapng tcp port 443
```

将明文数据以 pcap-NG 格式保存，支持 HTTP 1.0/1.1/2.0 (TCP) 和 HTTP/3 QUIC (UDP)。

### Keylog 模式

```bash
sudo ecapture tls -m keylog --keylogfile=ecapture_masterkey.log
```

保存 TLS Master Secret，可配合 Wireshark 解密流量。

## CLI 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--libssl` | libssl.so 文件路径 | 自动检测 |
| `-m, --model` | 捕获模式：text / pcap / keylog | text |
| `-k, --keylogfile` | TLS 密钥文件路径 | `ecapture_openssl_key.log` |
| `-w, --pcapfile` | pcapng 文件路径 | `save.pcapng` |
| `-i, --ifname` | TC 挂载的网络接口 | - |
| `--ssl_version` | 手动指定 SSL 版本 | 自动检测 |
| `--cgroup_path` | cgroup v2 路径过滤 | - |

## 与 Wireshark 联动的完整流程

### 方法一：PcapNG 模式

```bash
# 1. 启动 eCapture 捕获
sudo ecapture tls -m pcap -i eth0 -w /tmp/capture.pcapng tcp port 443

# 2. 在其他终端产生流量
curl https://example.com

# 3. Ctrl+C 停止 eCapture

# 4. 用 Wireshark 打开 pcapng 文件即可查看明文
wireshark /tmp/capture.pcapng
```

### 方法二：Keylog 模式 + tcpdump

```bash
# 1. 启动 tcpdump 抓取加密流量
sudo tcpdump -i eth0 -w /tmp/encrypted.pcap port 443 &

# 2. 启动 eCapture 保存密钥
sudo ecapture tls -m keylog -k /tmp/keys.log &

# 3. 产生流量
curl https://example.com

# 4. 在 Wireshark 中打开 encrypted.pcap
#    编辑 → 首选项 → Protocols → TLS → (Pre)-Master-Secret log filename → /tmp/keys.log
```

## Android BoringSSL 特殊处理

Android 平台使用 BoringSSL 作为默认 SSL/TLS 库，需要指定 Android 系统的 libssl 路径：

```bash
sudo ecapture tls --libssl=/apex/com.android.conscrypt/lib64/libssl.so --ssl_version="boringssl 1.1.1"
```

## 源码参考

| 组件 | 路径 |
|------|------|
| 探针实现 | `internal/probe/openssl/` |
| CLI 入口 | `cli/cmd/tls.go` |
| eBPF 内核程序 | `kern/openssl_*_kern.c` |
| Master Key 提取 | `kern/openssl_masterkey*.h` |
