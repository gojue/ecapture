# GoTLS 捕获

## 概述

`gotls` 模块针对 Go 语言原生 TLS 实现（`crypto/tls` 包）进行明文捕获。由于 Go 的 TLS 实现不依赖 OpenSSL 等外部库，需要专门的探针来处理 Go 的调用约定和二进制格式。

## 工作原理

eCapture 通过 uprobe 挂钩以下 Go 函数：
- `crypto/tls.(*Conn).Write`：捕获 TLS 发送的明文
- `crypto/tls.(*Conn).Read`：捕获 TLS 接收的明文

## Go 调用约定差异

Go 1.17 引入了基于寄存器的调用约定（Register ABI），这影响了 eBPF 程序从函数参数中提取数据的方式：

| Go 版本 | 调用约定 | 参数传递方式 |
|---------|---------|-------------|
| Go 1.17 之前 | Stack-based | 参数通过栈传递 |
| Go 1.17+ | Register-based | 参数通过寄存器传递 |

eCapture 在 `kern/go_argument.h` 中处理这两种调用约定的差异。

## 使用方法

### 基本用法

```bash
sudo ecapture gotls --elfpath=/path/to/go_binary
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--elfpath` | Go 二进制程序路径 | - |
| `--hex` | 十六进制格式输出 | false |
| `--pid` | 目标进程 PID | 0（所有） |

### 使用示例

```bash
# 1. 确认内核支持 BTF
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF

# 2. 启动 eCapture（指定目标 Go 程序）
sudo ecapture gotls --elfpath=/home/user/go_https_client --hex

# 3. 在另一个终端运行目标 Go 程序
/home/user/go_https_client
```

## 已知限制

1. **需要符号表**：目标 Go 二进制不能是 stripped 的（`go build -ldflags="-s -w"` 会去除符号表），否则 eCapture 无法定位挂钩函数
2. **CGO 程序**：如果 Go 程序使用 CGO 调用外部 OpenSSL 库进行 TLS，应使用 `tls` 模块而非 `gotls`
3. **静态分析**：eCapture 需要在运行前分析 Go 二进制的 ELF 信息来确定函数偏移

## 源码参考

| 组件 | 路径 |
|------|------|
| 探针实现 | `internal/probe/gotls/` |
| CLI 入口 | `cli/cmd/gotls.go` |
| eBPF 内核程序 | `kern/gotls_kern.c` |
| Go 参数处理 | `kern/go_argument.h` |
