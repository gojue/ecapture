<!-- MarkdownTOC autolink="true" -->

- [eCapture 工作原理](#ecapture-工作原理)
- [eCapture 系统架构](#ecapture-系统架构)
- [编译方法](#编译方法)
    - [编译环境](#编译环境)
    - [未开启BTF的编译](#未开启btf的编译)
    - [交叉编译](#交叉编译)
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

针对个别程序使用的openssl类库是静态编译，也可以自行修改源码实现。若函数名不在符号表里，也可以自行反编译找到函数的offset偏移地址，填写到`UprobeOffset`
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

# 原理

## eBPF技术

参考[ebpf](https://ebpf.io)官网的介绍

## eBPF学习资料

* [eBPF PDF资料精选](https://github/gojue/ebpf-slide)
* [CFC4N的博客](https://www.cnxct.com)