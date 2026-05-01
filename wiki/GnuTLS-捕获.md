# GnuTLS 捕获

## 概述

`gnutls` 模块通过 eBPF uprobe 挂钩 GnuTLS 库的 `gnutls_record_recv` 和 `gnutls_record_send` 函数，捕获使用 GnuTLS 加密通讯的明文内容。

## 适用程序

以下程序通常使用 GnuTLS 作为 TLS 后端：
- `wget`（部分系统默认使用 GnuTLS）
- `curl --with-gnutls`（编译时选择 GnuTLS 后端的 curl）
- `GNOME` 生态系统中的网络组件
- 其他链接 `libgnutls.so` 的程序

## 支持的 GnuTLS 版本

eCapture 为不同版本的 GnuTLS 维护专门的 eBPF 内核程序：

| 版本 | eBPF 字节码 |
|------|------------|
| 3.6.12 | `gnutls_3_6_12_kern.c` |
| 3.6.13 | `gnutls_3_6_13_kern.c` |
| 3.7.0 | `gnutls_3_7_0_kern.c` |
| 3.7.3 | `gnutls_3_7_3_kern.c` |
| 3.7.7 | `gnutls_3_7_7_kern.c` |
| 3.8.4 | `gnutls_3_8_4_kern.c` |
| 3.8.7 | `gnutls_3_8_7_kern.c` |

## 使用方法

### 基本用法

```bash
# 自动发现 GnuTLS 库
sudo ecapture gnutls

# 手动指定库路径
sudo ecapture gnutls --libgnutls=/usr/lib/x86_64-linux-gnu/libgnutls.so.30
```

### 配合 wget 测试

```bash
# 终端 1：启动 eCapture
sudo ecapture gnutls

# 终端 2：使用 wget 发起请求
wget https://example.com -O /dev/null
```

## 与 OpenSSL 探针的选择建议

| 场景 | 推荐探针 |
|------|---------|
| 不确定目标程序使用哪个 TLS 库 | 先用 `tls`（OpenSSL），无输出再试 `gnutls` |
| 目标程序是 wget | 优先使用 `gnutls` |
| 目标程序是 curl | 取决于编译选项，通常使用 `tls`（OpenSSL） |
| 目标程序是 Firefox | 使用 `nss` |

可以通过 `ldd` 命令确认目标程序链接的 TLS 库：

```bash
ldd $(which wget) | grep -E "ssl|gnutls|nss"
```

## 源码参考

| 组件 | 路径 |
|------|------|
| 探针实现 | `internal/probe/gnutls/` |
| CLI 入口 | `cli/cmd/gnutls.go` |
| eBPF 内核程序 | `kern/gnutls_*_kern.c` |
