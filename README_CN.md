![](./images/ecapture-logo-400x400.jpg)

中文介绍 | [English](./README.md) | [日本語](./README_JA.md)

[![GitHub stars](https://img.shields.io/github/stars/gojue/ecapture.svg?label=Stars&logo=github)](https://github.com/gojue/ecapture)
[![GitHub forks](https://img.shields.io/github/forks/gojue/ecapture?label=Forks&logo=github)](https://github.com/gojue/ecapture)
[![CI](https://github.com/gojue/ecapture/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/gojue/ecapture/actions/workflows/code-analysis.yml)
[![Github Version](https://img.shields.io/github/v/release/gojue/ecapture?display_name=tag&include_prereleases&sort=semver)](https://github.com/gojue/ecapture/releases)

### eCapture(旁观者): 基于eBPF技术实现TLS加密的明文捕获，无需CA证书。

> **Note:**
>
> 支持Linux系统内核x86_64 4.18及以上版本，aarch64 5.5及以上版本；
>
> 不支持Windows、macOS系统。

官方网站： [https://ecapture.cc](https://ecapture.cc)

----

# eCapture旁观者

eCapture的中文名字为**旁观者**，即「**当局者迷，旁观者清**」，与其本身功能**旁路、观察**契合，且发音与英文有相似之处。

# eCapture 工作原理

![](./images/how-ecapture-works.png)

eBPF `Uprobe`/`Traffic Control`实现的各种用户空间/内核空间的数据捕获，无需改动原程序。

* SSL/HTTPS数据导出功能，针对HTTPS的数据包抓取，不需要导入CA证书。
* 支持go tls类库的明文捕获，即使用golang语言编写的https/tls程序的加密通讯。
* bash的命令捕获，HIDS的bash命令监控解决方案。
* mysql query等数据库的数据库审计解决方案。

# 演示

## eCapture 使用方法
### 介绍文章
[eCapture：无需CA证书抓https明文通讯](https://mp.weixin.qq.com/s/DvTClH3JmncpkaEfnTQsRg)

### 演示视频
#### Linux上使用eCapture
![](./images/ecapture-help-v0.7.4.png)

#### Android上使用eCapture
[![eCapture User Manual](./images/ecapture-user-manual-on-android.png)](https://www.bilibili.com/video/BV1xP4y1Z7HB "eCapture for Android")
# 使用

## 直接运行

下载 [release](https://github.com/gojue/ecapture/releases) 的二进制包，可直接使用。

系统配置要求

* 系统linux kernel版本必须高于4.18。
* 开启BTF [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html) 支持。 (可选, 2022-04-17)

## 命令参数

> **Note**
>
> 需要ROOT权限执行。

执行`./ecapture -h`查看详细帮助文档。

eCapture默认查找`/etc/ld.so.conf`文件，查找SO文件的加载目录，并查找`openssl`等动态链接路位置。你也可以通过`--libssl`
参数指定动态链接库路径。

如果目标程序使用静态编译方式，则可以直接将`--libssl`参数设定为该程序的路径。

## 模块介绍
eCapture 有8个模块，分别支持openssl/gnutls/nspr/boringssl/gotls等类库的TLS/SSL加密类库的明文捕获、Bash、Mysql、PostGres软件审计。
* bash		capture bash command
* gnutls	capture gnutls text content without CA cert for gnutls libraries.
* gotls		Capturing plaintext communication from Golang programs encrypted with TLS/HTTPS.
* mysqld	capture sql queries from mysqld 5.6/5.7/8.0 .
* nss		capture nss/nspr encrypted text content without CA cert for nss/nspr libraries.
* postgres	capture sql queries from postgres 10+.
* tls		use to capture tls/ssl text content without CA cert. (Support openssl 1.0.x/1.1.x/3.0.x or newer).

你可以通过`ecapture -h`来查看这些自命令列表。

## openssl  模块
openssl模块支持3中捕获模式
* pcap/pcapng模式，将捕获的明文数据以pcap-NG格式存储。
* keylog/key模式，保存TLS的握手密钥到文件中。
* text模式，直接捕获明文数据，输出到指定文件中，或者打印到命令行。
### Pcap 模式
你可以通过`-m pcap`或`-m pcapng`参数来指定，需要配合`--pcapfile`、`-i`参数使用。其中`--pcapfile`参数的默认值为`ecapture_openssl.pcapng`。
```shell
./ecapture tls -m pcap -i eth0 --pcapfile=ecapture.pcapng tcp port 443
```
将捕获的明文数据包保存为pcapng文件，可以使用`Wireshark`打开查看。

### keylog 模式
你可以通过`-m keylog`或`-m key`参数来指定，需要配合`--keylogfile`参数使用，默认为`ecapture_masterkey.log`。
捕获的openssl TLS的密钥`Master Secret`信息，将保存到`--keylogfile`中。你也可以同时开启`tcpdump`抓包，再使用`Wireshark`打开，设置`Master Secret`路径，查看明文数据包。
```shell
./ecapture tls -m keylog -keylogfile=openssl_keylog.log
```

也可以直接使用`tshark`软件实时解密展示。
```shell
tshark -o tls.keylog_file:ecapture_masterkey.log -Y http -T fields -e http.file_data -f "port 443" -i eth0
```
### text 模式
`./ecapture tls -m text ` 将会输出所有的明文数据包。（v0.7.0起，不再捕获SSLKEYLOG信息。）


## gotls 模块
与openssl模块类似。

### 验证方法：

```shell
cfc4n@vm-server:~$# uname -r
4.18.0-305.3.1.el8.x86_64
cfc4n@vm-server:~$# cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF=y
```

### 启动eCapture
```shell
./ecapture gotls --elfpath=/home/cfc4n/go_https_client --hex
```

### 启动该程序:
确保该程序会触发https请求。
```shell
/home/cfc4n/go_https_client
```
### 更多帮助
```shell
./ecapture gotls -h
```


### bash的shell捕获
capture bash command : `ecapture bash`
```shell
ps -ef | grep foo
```

# eCapture 系统架构
![](./images/ecapture-architecture.png)

# 微信公众号
![](./images/wechat_gzhh.png)

## 自行编译
自行编译对编译环境有要求，参考**原理**章节的介绍。

# 原理
## eBPF技术
参考[ebpf](https://ebpf.io)官网的介绍

# 编译方法

针对个别程序使用的openssl类库是静态编译，也可以自行修改源码实现。若函数名不在符号表里，也可以自行反编译找到函数的offset偏移地址，填写到`UprobeOffset`属性上，进行编译。
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

## Stargazers over time

[![Stargazers over time](https://starchart.cc/gojue/ecapture.svg)](https://starchart.cc/gojue/ecapture)


# 贡献
参考 [CONTRIBUTING](./CONTRIBUTING.md)的介绍，提交issue、PR等，非常感谢。
