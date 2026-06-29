# eCapture Windows 版本技术分析报告

> 基于 ETW (Event Tracing for Windows) 的 TLS 明文捕获方案


---

## 1. 执行摘要

本报告对 eCapture 项目进行了全面的架构分析，并设计了将其移植到 Windows 平台的完整方案。eCapture 是一个基于 eBPF 技术的安全审计工具，能够在不需要 CA 证书的情况下捕获 SSL/TLS 明文数据。当前仅支持 Linux/Android 平台。

Windows 版本采用 ETW (Event Tracing for Windows) + 用户态函数钩子 (User-mode Hooking) 的技术方案，替代 Linux 上的 eBPF uprobes/kprobes。已完成全部 48 个新文件的创建和 20+ 个现有文件的修改，所有规划阶段均已实现并通过编译验证。

## 2. 项目架构分析

### 2.1 核心架构

eCapture 采用工厂模式 + 模板方法模式 + 观察者模式的架构设计，整体数据流如下：

| 层级 | 组件 | 职责 |
|------|------|------|
| CLI 层 | `cli/cmd/` | Cobra 命令解析、参数处理、环境检测 |
| 工厂层 | `internal/factory/` | 注册表模式管理探针构造函数 |
| 探针层 | `internal/probe/` | eBPF 程序加载、事件解码、生命周期 |
| 输出层 | `internal/output/` | Writer + Encoder 组合模式输出事件 |
| 内核层 | `kern/*.c` | eBPF C 程序，通过 uprobes/kprobes 捕获数据 |
| 域接口 | `internal/domain/` | Probe, Event, Configuration 等核心抽象 |

### 2.2 探针模块一览

| 探针 | 目标 | 钩子类型 |
|------|------|----------|
| OpenSSL | libssl.so / Schannel | uprobe: SSL_read/SSL_write |
| GoTLS | Go crypto/tls | uprobe: crypto/tls.Read/Write |
| Bash | bash + libreadline | uprobe: readline/execute_command |
| GnuTLS | libgnutls.so | uprobe: gnutls_record_send/recv |
| MySQL | mysqld | uprobe: dispatch_command |
| PostgreSQL | postgres | uprobe: exec_simple_query |
| NSPR | libnspr4.so | uprobe: PR_Read/PR_Write |
| Zsh | zsh | uprobe: zle_main |

### 2.3 构建系统

eCapture 使用 Makefile + clang + go-bindata 的构建流程。核心步骤为：编译 `kern/*.c` 为 eBPF 字节码 (`.o`) → go-bindata 嵌入为 Go 资源 → CGO 静态链接 libpcap → 编译 Go 二进制。支持 CO-RE 和 non-CO-RE 两种模式。

## 3. Windows 移植方案

### 3.1 技术选型对比

| 方案 | 优势 | 劣势 |
|------|------|------|
| **ETW (已选择)** | 微软官方支持，无需内核驱动，稳定性高 | 无法 hook 任意用户态函数 |
| ebpf-for-windows | 可复用部分 eBPF C 代码 | 不支持 uprobes，仅支持 XDP |
| 内核驱动 | 功能最强大 | 需要 WHQL 签名，开发成本极高 |

### 3.2 架构设计

Windows 版本采用与 Linux 版本相同的接口层 (`domain.Probe`)，但底层实现完全不同：

| 组件 | Linux 实现 | Windows 实现 |
|------|-----------|-------------|
| 数据采集 | eBPF uprobes/kprobes | ETW Provider + 纯 Go x64 内联 Hooking |
| TLS 库 | OpenSSL libssl.so | Schannel (secur32.dll) + OpenSSL DLL |
| Shell 捕获 | bash uprobes (readline) | ETW PowerShell Provider + cmd.exe |
| 包捕获 | TC classifier + libpcap | Npcap/WinPcap (gopacket/pcap) |
| 特权模型 | CAP_BPF / CAP_SYS_ADMIN | Administrator 权限 |
| CGO 依赖 | 静态链接 libpcap | 基础功能无需 CGO；Pcap 模式需 CGO (gopacket/pcap) |
| 构建方式 | make all (Linux 主机) | GOOS=windows CGO_ENABLED=0 |

### 3.3 Windows 版本探针功能矩阵

| 探针 | Windows 状态 | 实现方式 |
|------|-------------|---------|
| TLS (OpenSSL/Schannel) | ✅ 已实现 | ETW Schannel Provider + DLL Hooking |
| GoTLS | ✅ 已实现 | PE 符号解析 + 函数钩子 |
| Bash/Shell | ✅ 已实现 | ETW PowerShell + cmd.exe 事件 |
| MySQL | ✅ 已实现 | mysql_real_query DLL Hooking |
| PostgreSQL | ✅ 已实现 | PQexec DLL Hooking |
| GnuTLS | ⚠️ Stub | 返回"not supported"错误 |
| NSPR | ⚠️ Stub | 返回"not supported"错误 |
| Zsh | ⚠️ Stub | 返回"not supported"错误 |

## 4. 新增文件清单

### 4.1 底层工具包

| 文件路径 | 说明 |
|---------|------|
| `pkg/util/etw/etw_windows.go` | ETW 会话管理、Provider 注册、事件回调 |
| `pkg/util/etw/etw_stub.go` | 非 Windows 平台的 ETW 存根 |
| `pkg/util/etw/schannel_windows.go` | Schannel ETW 事件解析: 握手完成/失败/密钥/证书/告警 |
| `pkg/util/hook/hook_windows.go` | 用户态函数钩子管理器 (引用计数模块管理) |
| `pkg/util/hook/hook_stub.go` | 非 Windows 平台的 Hook 存根 |
| `pkg/util/hook/trampoline_windows.go` | x64 内联 Hook 实现: Trampoline + 指令长度解码 |
| `pkg/util/pcap/npcap_windows.go` | Npcap/WinPcap 包捕获封装 (gopacket/pcap) |

### 4.2 平台适配层

| 文件路径 | 说明 |
|---------|------|
| `pkg/util/kernel/kernel_version_windows.go` | Windows 内核版本检测 (RtlGetVersion) |
| `pkg/util/kernel/version_windows.go` | Windows 平台 Version 类型实现 |
| `pkg/util/kernel/version_nowindows.go` | 非 Windows 平台 hostVersionWindows 存根 |
| `pkg/util/kernel/version_nonlinux.go` | 非 Linux 平台 Version/HostVersion/ParseVersion |
| `pkg/util/ebpf/bpf_windows.go` | Windows eBPF 配置存根 |
| `pkg/util/ebpf/cgroup_windows.go` | Windows cgroup 存根 (返回 0) |

### 4.3 探针实现

| 文件路径 | 说明 |
|---------|------|
| `internal/probe/openssl/config_windows.go` | Windows TLS 配置: Schannel + OpenSSL DLL 检测 |
| `internal/probe/openssl/openssl_probe_windows.go` | Windows TLS 探针: ETW + 函数钩子实现 |
| `internal/probe/openssl/register_windows.go` | Windows TLS 探针注册 |
| `internal/probe/bash/config_windows.go` | Windows Shell 配置: PowerShell/cmd/bash 检测 |
| `internal/probe/bash/bash_probe_windows.go` | Windows Shell 探针: ETW 事件采集 |
| `internal/probe/bash/register_windows.go` | Windows Shell 探针注册 |
| `internal/probe/gotls/config_windows.go` | Windows GoTLS 配置 |
| `internal/probe/gotls/gotls_probe_windows.go` | Windows GoTLS 探针: PE 符号 + Hooking |
| `internal/probe/gotls/register_windows.go` | Windows GoTLS 探针注册 |
| `internal/probe/mysql/config_windows.go` | Windows MySQL 配置: DLL 路径检测 |
| `internal/probe/mysql/mysql_probe_windows.go` | Windows MySQL 探针: mysql_real_query Hooking |
| `internal/probe/mysql/event_windows.go` | Windows MySQL 事件定义 |
| `internal/probe/mysql/register_windows.go` | Windows MySQL 探针注册 |
| `internal/probe/postgres/config_windows.go` | Windows PostgreSQL 配置: DLL 路径检测 |
| `internal/probe/postgres/postgres_probe_windows.go` | Windows PostgreSQL 探针: PQexec Hooking |
| `internal/probe/postgres/event_windows.go` | Windows PostgreSQL 事件定义 |
| `internal/probe/postgres/register_windows.go` | Windows PostgreSQL 探针注册 |
| `internal/probe/base/base_probe_windows.go` | Windows 下 base 包的常量定义 |

### 4.4 Stub 探针 (Windows 不支持)

| 文件路径 | 说明 |
|---------|------|
| `internal/probe/gnutls/register_windows.go` | GnuTLS stub: 返回 not supported |
| `internal/probe/nspr/register_windows.go` | NSPR stub: 返回 not supported |
| `internal/probe/zsh/register_windows.go` | Zsh stub: 返回 not supported |

### 4.5 CLI 层

| 文件路径 | 说明 |
|---------|------|
| `cli/cmd/env_detection_windows.go` | Windows 环境检测: 版本 + 管理员权限 |
| `cli/cmd/tls_windows.go` | Windows TLS 子命令 (--schannel 标志) |
| `cli/cmd/bash_windows.go` | Windows Shell 子命令 (--shell-type 标志) |
| `cli/cmd/gotls_windows.go` | Windows GoTLS 子命令 |
| `cli/cmd/mysqld_windows.go` | Windows MySQL 子命令 |
| `cli/cmd/postgres_windows.go` | Windows PostgreSQL 子命令 |
| `cli/cmd/upgrade_windows.go` | Windows 升级存根 |
| `cli/http/config_factory_windows.go` | HTTP 配置工厂 stub |

### 4.6 E2E 测试套件

| 文件路径 | 说明 |
|---------|------|
| `test/e2e/windows/common_windows.ps1` | 公共辅助函数: 管理员检测、进程管理、输出验证 |
| `test/e2e/windows/windows_tls_test.ps1` | TLS 捕获测试: Text 模式 + Keylog 模式 |
| `test/e2e/windows/windows_bash_test.ps1` | Shell 捕获测试: PowerShell + cmd 模式 |
| `test/e2e/windows/windows_pcap_test.ps1` | Pcap 网络包捕获测试 |
| `test/e2e/windows/windows_mysql_test.ps1` | MySQL 查询捕获测试 |
| `test/e2e/windows/windows_postgres_test.ps1` | PostgreSQL 查询捕获测试 |

## 5. 修改的现有文件

### 5.1 Build Tag 变更

以下文件的 build tag 从 `!ecap_android` 更新为 `!ecap_android && !windows`，确保 Linux 专属代码不在 Windows 上编译：

| 文件 | 变更 |
|------|------|
| `internal/probe/openssl/config_linux.go` | `!ecap_android` → `!ecap_android && !windows` |
| `internal/probe/gnutls/register.go` | `!ecap_android` → `!ecap_android && !windows` |
| `internal/probe/mysql/register.go` | `!ecap_android` → `!ecap_android && !windows` |
| `internal/probe/postgres/register.go` | `!ecap_android` → `!ecap_android && !windows` |
| `internal/probe/nspr/register.go` | `!ecap_android` → `!ecap_android && !windows` |
| `internal/probe/zsh/register.go` | `!ecap_android` → `!ecap_android && !windows` |
| `cli/cmd/gnutls.go` | `!ecap_android` → `!ecap_android && !windows` |
| `cli/cmd/mysqld.go` | `!ecap_android` → `!ecap_android && !windows` |
| `cli/cmd/postgres.go` | `!ecap_android` → `!ecap_android && !windows` |
| `cli/cmd/nss.go` | `!ecap_android` → `!ecap_android && !windows` |
| `cli/cmd/zsh.go` | `!ecap_android` → `!ecap_android && !windows` |
| `cli/http/config_factory_linux.go` | `!ecap_android` → `!ecap_android && !windows` |
| `pkg/util/ebpf/bpf_linux.go` | `!ecap_android` → `!ecap_android && !windows` |
| `pkg/util/ebpf/cgroup_linux.go` | `!ecap_android` → `!ecap_android && !windows` |

### 5.2 新增 Build Tag 的文件

以下文件原本没有 build tag，因包含 Linux 专属代码而添加了 `!windows` 标记：

| 文件 | 原因 |
|------|------|
| `cli/cmd/env_detection.go` | 使用 `golang.org/x/sys/unix`、检测 Linux 内核版本 |
| `cli/cmd/tls.go` | 定义与 Windows 版本冲突的命令变量 |
| `cli/cmd/bash.go` | 定义与 Windows 版本冲突的命令变量 |
| `cli/cmd/gotls.go` | 定义与 Windows 版本冲突的命令变量 |
| `internal/probe/base/base_probe.go` | 导入 `cilium/ebpf/perf`、`ringbuf` (Linux 专属) |
| `internal/probe/base/base_probe_test.go` | 测试引用 BaseProbe |
| `internal/probe/base/perf_reorder_test.go` | 测试引用 perf 相关类型 |
| `internal/probe/openssl/openssl_probe.go` | 使用 eBPF manager、unix syscall |
| `internal/probe/openssl/event.go` | 使用 `golang.org/x/sys/unix` |
| `internal/probe/openssl/event_connect.go` | 使用 `golang.org/x/sys/unix` |
| `internal/probe/openssl/config.go` | 使用 `debug/elf` (Linux 专属) |
| `internal/probe/bash/bash_probe.go` | 使用 eBPF manager、unix syscall |
| `internal/probe/bash/config.go` | 使用 `debug/elf` (Linux 专属) |
| `internal/probe/gotls/gotls_probe.go` | 使用 eBPF manager、unix syscall |
| `internal/probe/gotls/config.go` | 使用 `debug/elf` (Linux 专属) |
| `internal/probe/gotls/config_symbol.go` | 使用 `debug/elf` |
| `internal/probe/gnutls/gnutls_probe.go` | 使用 eBPF manager |
| `internal/probe/mysql/mysql_probe.go` | 使用 eBPF manager |
| `internal/probe/mysql/event.go` | 使用 `golang.org/x/sys/unix` |
| `internal/probe/postgres/postgres_probe.go` | 使用 eBPF manager |
| `internal/probe/postgres/event.go` | 使用 `golang.org/x/sys/unix` |
| `internal/probe/nspr/nspr_probe.go` | 使用 eBPF manager |
| `internal/probe/zsh/zsh_probe.go` | 使用 eBPF manager |
| `internal/probe/zsh/event.go` | 使用 `golang.org/x/sys/unix` |
| `pkg/util/ebpf/bpf.go` | 使用 `golang.org/x/sys/unix` |
| `cli/cmd/upgrade.go` | 使用 `golang.org/x/sys/unix` |

### 5.3 其他修改

- **Makefile**: 新增 `windows` 和 `windows-arm64` 构建目标，更新 help 输出
- **cli/cmd/root.go**: 更新 `CliDescription` 和 `Long` 描述以包含 Windows 平台信息

## 6. 关键技术实现细节

### 6.1 ETW 集成

Windows 版本的核心是 ETW (Event Tracing for Windows) 集成。通过 `advapi32.dll` 的 `StartTraceW`/`EnableTraceEx2`/`ProcessTrace` API 实现：

- **Schannel Provider** — 捕获 TLS 手动完成、密钥交换、证书验证等事件
- **PowerShell Provider** — 捕获 PowerShell 脚本执行和命令输入
- **Security Auditing Provider** — 捕获 cmd.exe 进程创建和命令行参数

### 6.2 函数钩子架构

`pkg/util/hook` 包提供了纯 Go 实现的 x64 内联函数钩子，支持对 Windows DLL 导出函数的拦截：

- **HookManager** — 钩子管理器，支持引用计数模块加载 (`loadModuleRef`/`freeModuleRef`)，双重检查锁定防竞态
- **Trampoline** — x64 内联 Hook 实现: 最小指令长度解码器 + 绝对跳转 (mov rax, addr; jmp rax) + `FlushInstructionCache`
- `HookManager.AddHook()` — 注册并安装新的函数钩子
- `HookManager.Remove()` — 移除指定钩子并恢复原始字节
- `HookManager.Close()` — 批量清理所有钩子并释放模块引用
- `Hook.InvokeOriginal()` — 通过 Trampoline 调用原始函数

### 6.3 平台检测机制

Windows 版本的环境检测包括：

- Windows 版本检查：要求 Windows 10 Build 17763+ (版本 1809)，通过 RtlGetVersion API
- 管理员权限检查：验证进程是否具有 Administrators 组成员身份
- 架构检查：仅支持 amd64 和 arm64

## 7. 构建说明

Windows 版本从 Linux 主机交叉编译，无需 eBPF 工具链：

| 命令 | 说明 |
|------|------|
| `make windows` | 交叉编译 Windows amd64 版本 |
| `make windows-arm64` | 交叉编译 Windows arm64 版本 |

构建参数：`CGO_ENABLED=0`，`GOOS=windows`，基础版本不依赖 eBPF 字节码。Pcap 模式需 `CGO_ENABLED=1` 并链接 Npcap/WinPcap。产生的二进制文件位于 `bin/ecapture.exe`。

### 7.1 发布流程

Windows 版本已纳入 GitHub Actions 自动发布流程（推送 `v*` 标签触发）。在 `builder/Makefile.release` 中通过 `release_windows` target 顺序构建 amd64 和 arm64 两个架构的 zip 包：

| 命令 | 说明 |
|------|------|
| `make -f builder/Makefile.release release_windows` | 构建 Windows amd64 + arm64 zip 包 |
| `make -f builder/Makefile.release snapshot_windows` | 仅构建 Windows amd64 zip 包 |
| `make -f builder/Makefile.release snapshot_windows_arm64` | 仅构建 Windows arm64 zip 包 |

发布产物为 `.zip` 格式（Linux/Android 使用 `.tar.gz`），每个 zip 包含 `ecapture.exe`、`LICENSE`、`README.md`、`README-zh_Hans.md`。产物命名：

- `ecapture-{ver}-windows-amd64.zip`
- `ecapture-{ver}-windows-arm64.zip`

CI 流程中，Windows 构建作为独立步骤运行在 Linux/Android 构建之后、Publish 之前，`publish` target 通过 `ls` glob 自动收集所有 `.zip` 文件一并上传至 GitHub Release。

## 8. 路线图完成情况

所有规划阶段均已完成实现：

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 1 | ETW Schannel 事件解析，实现 TLS 明文捕获 | ✅ 已完成 |
| Phase 2 | 纯 Go x64 内联函数钩子 (Trampoline)，实现 DLL 函数拦截 | ✅ 已完成 |
| Phase 3 | Npcap/WinPcap 支持，实现 pcap 模式网络包捕获 | ✅ 已完成 |
| Phase 4 | Windows 下 MySQL/PostgreSQL 命令捕获 (DLL Hooking) | ✅ 已完成 |
| Phase 5 | Windows 专属 e2e 测试套件 (PowerShell) | ✅ 已完成 |
| Phase 6 | CI/CD 集成: GitHub Actions 自动构建并发布 Windows 版本 | ✅ 已完成 |
