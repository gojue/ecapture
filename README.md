[简体中文介绍](./README_CN.md)

----
[![GitHub stars](https://img.shields.io/github/stars/ehids/ecapture.svg?label=Stars&logo=github)](https://github.com/ehids/ecapture)
[![GitHub forks](https://img.shields.io/github/forks/ehids/ecapture?label=Forks&logo=github)](https://github.com/ehids/ecapture)
[![CI](https://github.com/ehids/ecapture/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/ehids/ecapture/actions/workflows/code-analysis.yml)
[![Github Version](https://img.shields.io/github/v/release/ehids/ecapture?display_name=tag&include_prereleases&sort=semver)](https://github.com/ehids/ecapture/releases)

#  How eCapture works

![](./images/how-ecapture-works.png)

* SSL/TLS text context capture, support openssl\gnutls\nspr(nss) librarys.
* bash aduit, capture bash command for Host Security Aduot.
* mysql query SQL aduit, support mysqld 5.6\5.7\8.0, and mariadDB.

# eCapture Architecure
![](./images/ecapture-architecture.png)

# eCapture User Manual
[![eCapture User Manual](./images/ecapture-user-manual.png)](https://www.youtube.com/watch?v=CoDIjEQCvvA "eCapture User Manual")

# Getting started
## use ELF binary file
Download ELF zip file [release](https://github.com/ehids/ecapture/releases) , unzip and use by command `./ecapture --help`.


* Linux kernel version >= 4.18
* Enable BTF [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html) 

### check your server BTF config：
```shell
cfc4n@vm-server:~$# uname -r
4.18.0-305.3.1.el8.x86_64
cfc4n@vm-server:~$# cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF=y
```

### tls command
capture tls text context.
Setp 1:
```shell
./ecapture tls --hex
```

Setp 2:
```shell
curl https://github.com
```

### bash command
capture bash command.
```shell
ps -ef | grep foo
```

# What's eBPF
[eBPF](https://ebpf.io)

## uprobe HOOK

### openssl hook 
eCapture hook`SSL_write` \ `SSL_read` function of shared library `/lib/x86_64-linux-gnu/libssl.so.1.1`. get text context, and send message to user space by eBPM map.
```go
Probes: []*manager.Probe{
    {
        Section:          "uprobe/SSL_write",
        EbpfFuncName:     "probe_entry_SSL_write",
        AttachToFuncName: "SSL_write",
        //UprobeOffset:     0x386B0,
        BinaryPath: "/lib/x86_64-linux-gnu/libssl.so.1.1",
    },
    {
        Section:          "uretprobe/SSL_write",
        EbpfFuncName:     "probe_ret_SSL_write",
        AttachToFuncName: "SSL_write",
        //UprobeOffset:     0x386B0,
        BinaryPath: "/lib/x86_64-linux-gnu/libssl.so.1.1",
    },
    {
        Section:          "uprobe/SSL_read",
        EbpfFuncName:     "probe_entry_SSL_read",
        AttachToFuncName: "SSL_read",
        //UprobeOffset:     0x38380,
        BinaryPath: "/lib/x86_64-linux-gnu/libssl.so.1.1",
    },
    {
        Section:          "uretprobe/SSL_read",
        EbpfFuncName:     "probe_ret_SSL_read",
        AttachToFuncName: "SSL_read",
        //UprobeOffset:     0x38380,
        BinaryPath: "/lib/x86_64-linux-gnu/libssl.so.1.1",
    },
    /**/
},
```
### bash readline.so hook
hook `/bin/bash` `readline` symbol name.

# How to compile
Linux Kernel: >= 4.18.

## Tools 
* golang 1.16
* gcc 10.3.0
* clang 12.0.0  
* cmake 3.18.4
* clang backend: llvm 12.0.0   
* pahole >= v1.13
* kernel config:CONFIG_DEBUG_INFO_BTF=y

## command
```shell
git clone git@github.com:ehids/ecapture.git
cd ecapture
make
bin/ecapture
```

# Contributing
See [CONTRIBUTING](./CONTRIBUTING.md) for details on submitting patches and the contribution workflow.