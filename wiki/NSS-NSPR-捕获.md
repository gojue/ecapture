# NSS / NSPR 捕获

## 概述

`nss` 模块通过 eBPF uprobe 挂钩 NSPR（Netscape Portable Runtime）库的 `PR_Read` 和 `PR_Write` 函数，捕获使用 NSS/NSPR 加密通讯的明文内容。

## 适用程序

NSS（Network Security Services）是 Mozilla 开发的安全库套件，以下程序使用 NSS 作为 TLS 后端：

- **Firefox**（浏览器）
- **Thunderbird**（邮件客户端）
- `curl --with-nss`（编译时选择 NSS 后端的 curl）
- 其他链接 `libnspr4.so` / `libnss3.so` 的程序

## 使用方法

### 基本用法

```bash
# 自动发现 NSPR 库
sudo ecapture nss

# 手动指定库路径
sudo ecapture nss --nspr=/usr/lib/x86_64-linux-gnu/libnspr4.so
```

### 配合 Firefox 测试

```bash
# 终端 1：启动 eCapture
sudo ecapture nss --pid=$(pidof firefox)

# 终端 2：在 Firefox 中浏览网页
```

## 与其他探针的区别

| 特性 | NSS/NSPR | OpenSSL | GnuTLS |
|------|----------|---------|--------|
| 主要用户 | Firefox, Thunderbird | nginx, curl, 大多数服务器 | wget, GNOME 组件 |
| 挂钩函数 | PR_Read/PR_Write | SSL_read/SSL_write | gnutls_record_recv/send |
| eBPF 程序 | 单一版本 | 多版本分支 | 多版本分支 |

## 如何确定使用哪个探针

```bash
# 检查目标程序链接的 TLS 库
ldd $(which firefox) | grep -E "ssl|gnutls|nss|nspr"

# 如果看到 libnspr4.so 或 libnss3.so，使用 nss 模块
# 如果看到 libssl.so，使用 tls 模块
# 如果看到 libgnutls.so，使用 gnutls 模块
```

## 源码参考

| 组件 | 路径 |
|------|------|
| 探针实现 | `internal/probe/nspr/` |
| CLI 入口 | `cli/cmd/nss.go` |
| eBPF 内核程序 | `kern/nspr_kern.c` |
