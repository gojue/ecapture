# Shell 审计（Bash / Zsh）

## 概述

eCapture 提供 `bash` 和 `zsh` 两个探针模块，通过 uprobe 挂钩 Shell 的 readline 库函数，捕获用户输入的命令内容。适用于主机安全审计、合规审查等场景。

---

## Bash 命令捕获

### 工作原理

通过 uprobe 挂钩 `readline` 库的 `readline` 函数（或 bash 内置的 `rl_line_buffer`），在用户按下回车提交命令时捕获输入内容。

### 使用方法

```bash
# 自动发现当前环境的 bash
sudo ecapture bash

# 手动指定 bash 路径
sudo ecapture bash --bash=/bin/bash

# 手动指定 readline 库路径
sudo ecapture bash --readlineso=/lib/x86_64-linux-gnu/libreadline.so.8

# 只显示执行结果为特定错误码的命令
sudo ecapture bash -e 0  # 只显示执行成功的命令
```

### CLI 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--bash` | bash 可执行文件路径 | 自动从 `$SHELL` 发现 |
| `--readlineso` | readline.so 文件路径 | 自动从 bash 路径发现 |
| `-e, --errnumber` | 过滤错误码 | 128（显示所有） |

### 输出格式

```
PID: 1234 | UID: 1000 | User: ubuntu | Command: ls -la /tmp
PID: 1234 | UID: 1000 | User: ubuntu | Command: cat /etc/passwd
PID: 1234 | UID: 1000 | User: ubuntu | Command: sudo systemctl restart nginx
```

输出包含：
- **PID**：执行命令的进程 ID
- **UID**：用户 ID
- **User**：用户名
- **Command**：完整的命令内容
- **时间戳**：命令执行时间

---

## Zsh 命令捕获

### 工作原理

类似 Bash 探针，通过 uprobe 挂钩 Zsh 的 `zle_main` 相关函数捕获命令输入。

### 使用方法

```bash
# 自动发现 zsh
sudo ecapture zsh

# 手动指定 zsh 路径
sudo ecapture zsh --zsh=/bin/zsh
```

---

## 典型使用场景

### 1. 安全审计

记录所有用户的 Shell 操作，用于事后审查：

```bash
# 捕获所有用户的 bash 命令并保存到文件
sudo ecapture bash -l /var/log/ecapture_bash.log
```

### 2. 合规审查

满足等保、SOX、PCI DSS 等合规要求中对操作记录的要求。

### 3. 入侵检测

监控是否有异常的 Shell 命令执行：

```bash
# 实时监控所有 bash 命令
sudo ecapture bash
```

### 4. 容器环境审计

在 Kubernetes 节点上审计 Pod 内的 Shell 操作：

```bash
# 指定容器内的 bash 进程
sudo ecapture bash --pid=<container_bash_pid>
```

## 源码参考

| 组件 | 路径 |
|------|------|
| Bash 探针实现 | `internal/probe/bash/` |
| Zsh 探针实现 | `internal/probe/zsh/` |
| Bash CLI 入口 | `cli/cmd/bash.go` |
| Zsh CLI 入口 | `cli/cmd/zsh.go` |
| eBPF 内核程序 | `kern/bash_kern.c` |
