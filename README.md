![](./images/ecapture-logo-400x400.png)
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-13-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

[中文介绍](./README_CN.md) | English

[![GitHub stars](https://img.shields.io/github/stars/ehids/ecapture.svg?label=Stars&logo=github)](https://github.com/ehids/ecapture)
[![GitHub forks](https://img.shields.io/github/forks/ehids/ecapture?label=Forks&logo=github)](https://github.com/ehids/ecapture)
[![CI](https://github.com/ehids/ecapture/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/ehids/ecapture/actions/workflows/code-analysis.yml)
[![Github Version](https://img.shields.io/github/v/release/ehids/ecapture?display_name=tag&include_prereleases&sort=semver)](https://github.com/ehids/ecapture/releases)

### eCapture(旁观者):  capture SSL/TLS text content without CA cert Using eBPF.

> **Note**
>
> Support Linux Kernel 4.15 or newer,Support Android Kernel 5.4 or newer.
>
> Do not support Windows and macOS system.
----

#  How eCapture works

![](./images/how-ecapture-works.png)

* SSL/TLS text context capture, support openssl\libressl\boringssl\gnutls\nspr(nss) libraries.
* bash audit, capture bash command for Host Security Audit.
* mysql query SQL audit, support mysqld 5.6\5.7\8.0, and mariadDB.

# eCapture Architecture
![](./images/ecapture-architecture.png)

# eCapture User Manual

[![eCapture User Manual](./images/ecapture-user-manual.png)](https://www.youtube.com/watch?v=CoDIjEQCvvA "eCapture User Manual")

# Getting started

## use ELF binary file

Download ELF zip file [release](https://github.com/ehids/ecapture/releases) , unzip and use by
command `./ecapture --help`.

* Linux kernel version >= 4.15 is required.
* Enable BTF [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)  (Optional, 2022-04-17)

## Command line options

> **Note**
>
> Need ROOT permission.
>
eCapture search `/etc/ld.so.conf` file default, to search load directories of  `SO` file, and search `openssl` shard
libraries location. or you can use `--libssl`
flag to set shard library path.

If target program is compile statically, you can set program path as `--libssl` flag value directly。

### Pcapng result

`./ecapture tls -i eth0 -w pcapng -p 443` capture plaintext packets save as pcapng file, use `Wireshark` read it
directly.

### plaintext result

`./ecapture tls` will capture all plaintext context ,output to console, and capture `Master Secret` of `openssl TLS`
save to `ecapture_master.log`. You can also use `tcpdump` to capture raw packet,and use `Wireshark` to read them
with `Master Secret` settings.

>

### check your server BTF config：

```shell
cfc4n@vm-server:~$# uname -r
4.18.0-305.3.1.el8.x86_64
cfc4n@vm-server:~$# cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF=y
```

### tls command

capture tls text context.
Step 1:
```shell
./ecapture tls --hex
```

Step 2:
```shell
curl https://github.com
```

### libressl&boringssl
```shell
# for installed libressl, libssl.so.52 is the dynamic ssl lib
vm@vm-server:~$ ldd /usr/local/bin/openssl
	linux-vdso.so.1 (0x00007ffc82985000)
	libssl.so.52 => /usr/local/lib/libssl.so.52 (0x00007f1730f9f000)
	libcrypto.so.49 => /usr/local/lib/libcrypto.so.49 (0x00007f1730d8a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1730b62000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f17310b2000)

# use the libssl to config the libssl.so path
vm@vm-server:~$ sudo ./ecapture tls --libssl="/usr/local/lib/libssl.so.52" --hex

# in another terminal, use the command, then type some string, watch the output of ecapture
vm@vm-server:~$ /usr/local/bin/openssl s_client -connect github.com:443

# for installed boringssl, usage is the same
/path/to/bin/bssl s_client -connect github.com:443
```

### bash command
capture bash command.
```shell
ps -ef | grep foo
```

# What's eBPF
[eBPF](https://ebpf.io)

## uprobe HOOK

### openssl\libressl\boringssl hook
eCapture hook`SSL_write` \ `SSL_read` function of shared library `/lib/x86_64-linux-gnu/libssl.so.1.1`. get text context, and send message to user space by [eBPF maps](https://www.kernel.org/doc/html/latest/bpf/maps.html).
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
hook `/bin/bash` symbol name `readline`.

# How to compile

Linux Kernel: >= 4.15.

## Tools 
* golang 1.17
* clang 9.0
* cmake 3.18.4
* clang backend: llvm 9.0
* kernel config:CONFIG_DEBUG_INFO_BTF=y (Optional, 2022-04-17)

## command
```shell
sudo apt-get update
sudo apt-get install --yes build-essential pkgconf libelf-dev llvm-9 clang-9 linux-tools-common linux-tools-generic
for tool in "clang" "llc" "llvm-strip"
do
  sudo rm -f /usr/bin/$tool
  sudo ln -s /usr/bin/$tool-9 /usr/bin/$tool
done
git clone git@github.com:ehids/ecapture.git
cd ecapture
make
bin/ecapture --help
```

## compile without BTF
eCapture support BTF disabled with command `make nocore` to compile on 2022/04/17.
```shell
make nocore
bin/ecapture --help
```


# Contributing
See [CONTRIBUTING](./CONTRIBUTING.md) for details on submitting patches and the contribution workflow.

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center"><a href="https://www.cnxct.com"><img src="https://avatars.githubusercontent.com/u/709947?v=4?s=100" width="100px;" alt=""/><br /><sub><b>CFC4N</b></sub></a><br /><a href="#infra-cfc4n" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="https://github.com/ehids/ecapture/commits?author=cfc4n" title="Tests">⚠️</a> <a href="https://github.com/ehids/ecapture/commits?author=cfc4n" title="Code">💻</a></td>
      <td align="center"><a href="https://chenhengqi.com"><img src="https://avatars.githubusercontent.com/u/4277743?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Hengqi Chen</b></sub></a><br /><a href="#infra-chenhengqi" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="https://github.com/ehids/ecapture/commits?author=chenhengqi" title="Tests">⚠️</a> <a href="https://github.com/ehids/ecapture/commits?author=chenhengqi" title="Code">💻</a></td>
      <td align="center"><a href="https://chriskalix.github.io/"><img src="https://avatars.githubusercontent.com/u/46471110?v=4?s=100" width="100px;" alt=""/><br /><sub><b>chriskali</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=chriskaliX" title="Code">💻</a></td>
      <td align="center"><a href="https://github.com/huzai9527"><img src="https://avatars.githubusercontent.com/u/33509974?v=4?s=100" width="100px;" alt=""/><br /><sub><b>huzai9527</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=huzai9527" title="Code">💻</a></td>
      <td align="center"><a href="https://youtube.com/c/LinuxMonkinCloud"><img src="https://avatars.githubusercontent.com/u/3729694?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Vincent Li</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=vincentmli" title="Code">💻</a></td>
      <td align="center"><a href="http://yihong.run"><img src="https://avatars.githubusercontent.com/u/15976103?v=4?s=100" width="100px;" alt=""/><br /><sub><b>yihong</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=yihong0618" title="Code">💻</a></td>
      <td align="center"><a href="https://blaise.wang/"><img src="https://avatars.githubusercontent.com/u/9657268?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Blaise Wang</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=blaisewang" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center"><a href="https://4ft35t.github.io/"><img src="https://avatars.githubusercontent.com/u/2051049?v=4?s=100" width="100px;" alt=""/><br /><sub><b>4ft35t</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=4ft35t" title="Code">💻</a></td>
      <td align="center"><a href="https://weishu.me"><img src="https://avatars.githubusercontent.com/u/4233744?v=4?s=100" width="100px;" alt=""/><br /><sub><b>weishu</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=tiann" title="Code">💻</a></td>
      <td align="center"><a href="http://www.dashen.tech"><img src="https://avatars.githubusercontent.com/u/15921519?v=4?s=100" width="100px;" alt=""/><br /><sub><b>cui fliter</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=cuishuang" title="Code">💻</a></td>
      <td align="center"><a href="https://nfsec.pl"><img src="https://avatars.githubusercontent.com/u/15172919?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Patryk Krawaczyński</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=nfsec" title="Code">💻</a></td>
      <td align="center"><a href="https://github.com/yindex"><img src="https://avatars.githubusercontent.com/u/38709569?v=4?s=100" width="100px;" alt=""/><br /><sub><b>yindex</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=yindex" title="Code">💻</a></td>
      <td align="center"><a href="https://github.com/xujiajiadexiaokeai"><img src="https://avatars.githubusercontent.com/u/30225423?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Wenhao Jiang</b></sub></a><br /><a href="https://github.com/ehids/ecapture/commits?author=xujiajiadexiaokeai" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->