<!-- MarkdownTOC autolink="true" -->

- [eCapture 工作原理](#ecapture-工作原理)
- [eCapture 系统架构](#ecapture-系统架构)
- [编译方法](#编译方法)
    - [编译环境](#编译环境)
    - [未开启BTF的编译](#未开启btf的编译)
    - [交叉编译](#交叉编译)
    - [Windows 编译](#windows-编译)
- [原理](#原理)
    - [eBPF技术](#ebpf技术)
    - [eBPF学习资料](#ebpf学习资料)
<!-- /MarkdownTOC -->
----

# eCapture 系统架构

![](./images/ecapture-architecture.png)

# eCapture 工作原理

![](./images/how-ecapture-works.png)

## 自行编译

自行编译对编译环境有要求，参考**原理**章节的介绍。

# 编译方法

针对个别程序使用的openssl类库是静态编译，也可以自行修改源码实现。若函数名不在符号表里，也可以自行反编译找到函数的offset偏移地址，填写到
`Uaddress`
属性上，进行编译。
笔者环境`ubuntu 21.04`， Linux Kernel 4.18以上通用。
**推荐使用`UBUNTU 20.04` 及以上版本的Linux测试。**

> **Note**
>
> Android版本编译方法见 [eCapture旁观者：Android HTTPS明文抓包](https://mp.weixin.qq.com/s/KWm5d0uuzOzReRtr9PmuWQ)

## 工具链版本

* golang 1.21 以上
* clang 9.0 以上
* cmake 3.18.4 以上
* clang backend: llvm 9.0 以上
* kernel config:CONFIG_DEBUG_INFO_BTF=y (可选，2022-04-17增加)

## 编译环境

### ubuntu

如果你使用的是ubuntu 20.04以及更新版本，可以使用一条命令即可完成编译环境的初始化。

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"
```

### 其他Linux

编译环境除了上面`工具链版本`列出的软件外，还需要以下软件，请自行安装。

* linux-tools-common
* linux-tools-generic
* pkgconf
* libelf-dev

**克隆仓库代码，并进行编译**

注意：如果系统里没有 `/usr/local/lib/libpcap.a`，则下面 `make` 命令会将 libpcap
编译并安装到 `/usr/local/lib` 目录下。如果系统里已经安装了 libpcap 但没有
`/usr/local/lib/libpcap.a`，则 `make` 命令会破坏系统里的 libpcap 头文件。

```shell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
make
bin/ecapture
```

如果你在中国，可以在`make`编译之前，设定GOPROXY来加速eCapture依赖的go package的安装。

```shell
export GOPROXY=https://goproxy.cn
```

## 未开启BTF的编译

2022/04/17起，eCapture支持了未开启BTF的系统编译，编译指令为：`make nocore`，即在不支持BTF的Linux上也可以正常工作。

```shell
git clone git@github.com:gojue/ecapture.git
cd ecapture
make nocore
bin/ecapture
```

## 交叉编译

### 内核头文件

要交叉编译eCapture工具，您需要安装目标体系结构的内核头文件。需要安装`linux-source`软件包。

```shell
kernel_ver=`uname -r | cut -d'-' -f 1`
sudo apt-get install -y linux-source-$kernel_ver
cd /usr/src
source_file=$(find . -maxdepth 1 -name "*linux-source*.tar.bz2")
source_dir=$(echo "$source_file" | sed 's/\.tar\.bz2//g')  
sudo tar -xf $source_file
cd $source_dir
test -f .config || yes "" | sudo make oldconfig
```

### ToolChains

在amd64架构下，交叉编译aarch64架构的二进制文件，需要安装gcc-aarch64-linux-gnu工具链。同样，在aarch64架构下，交叉编译amd64架构的二进制文件，需要安装gcc-x86-64-linux-gnu工具链。

* amd64 arch: gcc-aarch64-linux-gnu
* arm64 arch: gcc-x86-64-linux-gnu

### 编译命令

要在ubuntu `amd64` 系统上构建 `arm64`的产物，您可以设置 `CROSS_ARCH`环境变量来实现交叉编译。

```shell
CROSS_ARCH=arm64 make
```

## Windows 编译

eCapture 支持 Windows 平台（x86_64 和 arm64），使用 ETW（Event Tracing for Windows）替代 eBPF 实现流量捕获。Windows 版本通过 Schannel ETW 提供者捕获 TLS 流量，并支持对 OpenSSL、MySQL、PostgreSQL 的 DLL 函数钩子。

### Windows 编译环境要求

* **Go 1.21** 及以上
* **MinGW-w64** 交叉编译器（用于 CGO，pcap 模式必需）
  - Ubuntu 下安装：`sudo apt-get install -y gcc-mingw-w64-x86-64`
  - Windows 本地编译：安装 [MSYS2](https://www.msys2.org/) 并将 `mingw-w64` 添加到 PATH
* **Npcap**（可选，用于 pcap 模式）：从 [npcap.com](https://npcap.com/) 安装，需启用 "WinPcap API-compatible mode"
* **管理员权限**：运行时需要管理员权限（ETW 会话需要提升权限）

### 从 Linux 交叉编译

```shell
# Windows amd64 版本
make windows

# Windows arm64 版本
make windows-arm64
```

Windows 构建目标默认使用 `CGO_ENABLED=1` 以支持 Npcap/pcap 模式。如果不需要 pcap 模式，可以修改 Makefile 关闭 CGO。

### 在 Windows 上本地编译

```powershell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
$env:CGO_ENABLED = "1"
go build -tags windows -o bin/ecapture.exe main.go
```

如果你在中国，可以在编译之前设置 GOPROXY 来加速依赖包下载：

```powershell
$env:GOPROXY = "https://goproxy.cn,direct"
```

### Windows 功能列表

| 功能 | 说明 |
|------|------|
| TLS/Schannel 捕获 | 基于 ETW 的 Microsoft-Windows-Schannel 提供者捕获 |
| OpenSSL 钩子 | DLL 函数钩子捕获 `SSL_read`/`SSL_write` |
| MySQL/PostgreSQL 捕获 | DLL 钩子捕获 `mysql_real_query`/`PQexec` |
| pcap 模式 | 通过 Npcap 进行网络包捕获（需安装 Npcap） |
| keylog 模式 | TLS 密钥材料导出（NSS keylog 格式） |

### Windows E2E 测试

PowerShell 端到端测试脚本位于 `test/e2e/windows/` 目录，需要以管理员身份运行：

```powershell
cd test\e2e\windows
.\windows_tls_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
.\windows_bash_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
.\windows_mysql_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
.\windows_postgres_test.ps1 -EcaptureBinary "..\..\..\bin\ecapture.exe"
```

# 原理

## eBPF技术

参考[ebpf](https://ebpf.io)官网的介绍

## eBPF学习资料

* [eBPF PDF资料精选](https://github.com/gojue/ebpf-slide)
* [CFC4N的博客](https://www.cnxct.com)