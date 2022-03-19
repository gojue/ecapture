# ecapture 介绍
eBPF HOOK uprobe实现的各种用户态进程的数据捕获，无需改动原程序。
* SSL/HTTPS数据导出功能，针对HTTPS的数据包抓取，不需要导入CA证书。
* bash的命令捕获，HIDS的bash命令监控解决方案。
* mysql query等数据库的数据库审计解决方案。


# 演示

### 截图
![](./images/openssl-example.jpg)

### 视频
[https://v.qq.com/txp/iframe/player.html?vid=m33278fdqt8](https://v.qq.com/txp/iframe/player.html?vid=m33278fdqt8)


# 原理

## 依赖
### 内核版本
依赖[BPF BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) 格式，仅支持linux kernel 5.8以上内核版本，即以下linux发行版。
* CentOS 8.2
* CentOS Stream 8.3
* Alma 8.3
* Fedora 32
* Ubuntu 20.10

### eBPF配置
需要内核开启BTF支持。
```shell
cat /boot/config-`uname -r` | grep BTF
CONFIG_VIDEO_SONY_BTF_MPX=m
CONFIG_DEBUG_INFO_BTF=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
```

## eBPF技术
参考[ebpf](https://ebpf.io)官网的介绍

## uprobe HOOK

### https的ssl hook 
本项目hook了`/lib/x86_64-linux-gnu/libssl.so.1.1`的`SSL_write`、`SSL_read`函数的返回值，拿到明文信息，通过ebpf map传递给用户进程。
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
### bash的readline hook
hook了`/bin/bash`的`readline`函数。

# 使用方法
安装使用，可以选择编译，也可以直接下载二进制包。
笔者环境`ubuntu 21.04`， linux kernel 5.10以上通用。

**推荐使用`UBUNTU 21.04`版本的linux测试。**

## 工具链版本
* gcc 10.3.0
* clang 12.0.0  
* cmake 3.18.4
* clang backend: llvm 12.0.0   

### 最低要求 (笔者未验证)
* gcc 5.1 以上
* clang 9
* cmake 3.14


## 编译
```shell
git clone git@github.com:ehids/ecapture.git
cd ecapture
go get -d github.com/shuLhan/go-bindata/cmd/go-bindata
make
bin/ecapture
```
## 使用

### https的无证书抓包 ssldump
执行任意https网络请求即可使用。
```shell
curl https://www.qq.com
```

## 注意
已知centos 8.2的系统上，wget的网络行为无法获取，原因为wget没有使用openssl的so动态链接库`libssl.so`。如你遇到问题，请将详细信息提到[issue](https://github.com/ehids/ecapture/issues/new/choose) 里。

```shell
[root@localhost ~]# ldd /usr/bin/wget 
 linux-vdso.so.1 (0x00007ffe65bfb000)
 libuuid.so.1 => /lib64/libuuid.so.1 (0x00007f9d200a8000)
 libidn2.so.0 => /lib64/libidn2.so.0 (0x00007f9d1fe8a000)
 libgpgme.so.11 => /lib64/libgpgme.so.11 (0x00007f9d1fc41000)
 libmetalink.so.3 => /lib64/libmetalink.so.3 (0x00007f9d1fa30000)
 libnettle.so.6 => /lib64/libnettle.so.6 (0x00007f9d1f7f7000)
 libgnutls.so.30 => /lib64/libgnutls.so.30 (0x00007f9d1f43b000)
 libz.so.1 => /lib64/libz.so.1 (0x00007f9d1f224000)
 libpsl.so.5 => /lib64/libpsl.so.5 (0x00007f9d1f013000)
 libc.so.6 => /lib64/libc.so.6 (0x00007f9d1ec4e000)
 /lib64/ld-linux-x86-64.so.2 (0x00007f9d20537000)
 libunistring.so.2 => /lib64/libunistring.so.2 (0x00007f9d1e8cd000)
 libassuan.so.0 => /lib64/libassuan.so.0 (0x00007f9d1e6b9000)
 libgpg-error.so.0 => /lib64/libgpg-error.so.0 (0x00007f9d1e498000)
 libexpat.so.1 => /lib64/libexpat.so.1 (0x00007f9d1e25d000)
 libp11-kit.so.0 => /lib64/libp11-kit.so.0 (0x00007f9d1df2a000)
 libdl.so.2 => /lib64/libdl.so.2 (0x00007f9d1dd26000)
 libtasn1.so.6 => /lib64/libtasn1.so.6 (0x00007f9d1db13000)
 libhogweed.so.4 => /lib64/libhogweed.so.4 (0x00007f9d1d8e3000)
 libgmp.so.10 => /lib64/libgmp.so.10 (0x00007f9d1d64b000)
 libffi.so.6 => /lib64/libffi.so.6 (0x00007f9d1d442000)
 libpthread.so.0 => /lib64/libpthread.so.0 (0x00007f9d1d222000)
```

### bash的shell捕获
```shell
ps -ef | grep foo
```

# 技术交流群
![](./images/wechat-group.jpg)

# 参考资料
[BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)