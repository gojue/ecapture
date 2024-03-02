![](./images/ecapture-logo-400x400.png)

[中文介绍](./README_CN.md) | English | [日本語](./README_JA.md)

[![GitHub stars](https://img.shields.io/github/stars/gojue/ecapture.svg?label=Stars&logo=github)](https://github.com/gojue/ecapture)
[![GitHub forks](https://img.shields.io/github/forks/gojue/ecapture?label=Forks&logo=github)](https://github.com/gojue/ecapture)
[![CI](https://github.com/gojue/ecapture/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/gojue/ecapture/actions/workflows/code-analysis.yml)
[![Github Version](https://img.shields.io/github/v/release/gojue/ecapture?display_name=tag&include_prereleases&sort=semver)](https://github.com/gojue/ecapture/releases)

### eCapture(旁观者): capture SSL/TLS text content without a CA certificate using eBPF.

> **Note**
>
> Supports Linux/Android kernel versions x86_64 4.18 and above, **aarch64 5.5** and above.
> Does not support Windows and macOS system.
----

#  How eCapture works

![](./images/how-ecapture-works.png)

* SSL/TLS plaintext capture, support openssl\libressl\boringssl\gnutls\nspr(nss) libraries.
* GoTLS plaintext support go tls library, which refers to encrypted communication in https/tls programs written in the golang language.
* bash audit, capture bash command for Host Security Audit.
* mysql query SQL audit, support mysqld 5.6\5.7\8.0, and mariadDB.

# eCapture User Manual
![](./images/ecapture-help-v0.7.4.png)

Youtube video: [How to use eCapture v0.1.0](https://www.youtube.com/watch?v=CoDIjEQCvvA "eCapture User Manual")

# Getting started

## use ELF binary file

Download ELF zip file [release](https://github.com/gojue/ecapture/releases) , unzip and use by
command `./ecapture --help`.

* Linux kernel version >= 4.18 is required.
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

## Modules
The eCapture tool comprises 8 modules that respectively support plaintext capture for TLS/SSL encryption libraries like OpenSSL, GnuTLS, NSPR, BoringSSL, and GoTLS. Additionally, it facilitates software audits for Bash, MySQL, and PostgreSQL applications.
* bash		capture bash command
* gnutls	capture gnutls text content without CA cert for gnutls libraries.
* gotls		Capturing plaintext communication from Golang programs encrypted with TLS/HTTPS.
* mysqld	capture sql queries from mysqld 5.6/5.7/8.0 .
* nss		capture nss/nspr encrypted text content without CA cert for nss/nspr libraries.
* postgres	capture sql queries from postgres 10+.
* tls		use to capture tls/ssl text content without CA cert. (Support openssl 1.0.x/1.1.x/3.0.x or newer).
  You can use `ecapture -h` to view the list of subcommands.

## OpenSSL Module

The OpenSSL module supports three capture modes:

- `pcap`/`pcapng` mode stores captured plaintext data in pcap-NG format.
- `keylog`/`key` mode saves the TLS handshake keys to a file.
- `text` mode directly captures plaintext data, either outputting to a specified file or printing to the command line.

### Pcap Mode

You can specify `-m pcap` or `-m pcapng` and use it in conjunction with `--pcapfile` and `-i` parameters. The default value for `--pcapfile` is `ecapture_openssl.pcapng`.

```shell
./ecapture tls -m pcap -i eth0 --pcapfile=ecapture.pcapng tcp port 443
```

This command saves captured plaintext data packets as a pcapng file, which can be viewed using `Wireshark`.

### Keylog Mode

You can specify `-m keylog` or `-m key` and use it in conjunction with the `--keylogfile` parameter, which defaults to `ecapture_masterkey.log`.

The captured OpenSSL TLS `Master Secret` information is saved to `--keylogfile`. You can also enable `tcpdump` packet capture and then use `Wireshark` to open the file and set the `Master Secret` path to view plaintext data packets.

```shell
./ecapture tls -m keylog -keylogfile=openssl_keylog.log
```

You can also directly use the `tshark` software for real-time decryption and display:

```shell
tshark -o tls.keylog_file:ecapture_masterkey.log -Y http -T fields -e http.file_data -f "port 443" -i eth0
```

### Text Mode

`./ecapture tls -m text` will output all plaintext data packets. (Starting from v0.7.0, it no longer captures SSLKEYLOG information.)

## GoTLS Module

Similar to the OpenSSL module.

### check your server BTF config：

```shell
cfc4n@vm-server:~$# uname -r
4.18.0-305.3.1.el8.x86_64
cfc4n@vm-server:~$# cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF=y
```

### gotls command

capture tls text context.

Step 1:
```shell
./ecapture gotls --elfpath=/home/cfc4n/go_https_client --hex
```

Step 2:
```shell
/home/cfc4n/go_https_client
```
### more help
```shell
./ecapture gotls -h
```

## bash Module
capture bash command : `ecapture bash`
```shell
ps -ef | grep foo
```

# eCapture Architecture
![](./images/ecapture-architecture.png)

# What's eBPF
[eBPF](https://ebpf.io)

# How to compile
Linux Kernel: >= 4.18.

## Tools
* golang 1.21 or newer
* clang 9.0 or newer
* cmake 3.18.4 or newer
* clang backend: llvm 9.0 or newer
* kernel config:CONFIG_DEBUG_INFO_BTF=y (Optional, 2022-04-17)

## command

### ubuntu
If you are using Ubuntu 20.04 or later versions, you can use a single command to complete the initialization of the compilation environment.
```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"
```
### other Linux
In addition to the software listed in the 'Toolchain Version' section above, the following software is also required for the compilation environment. Please install it yourself.
* linux-tools-common
* linux-tools-generic
* pkgconf
* libelf-dev

**Clone the repository code and compile it**

Caution: The following `make` command will install libpcap into the system
directory if `libpcap.a` does not exist under `/usr/local/lib`. If you have
installed libpcap in system without `libpcap.a`, it maybe break your libpcap's
headers.

```shell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
make
bin/ecapture
```
## compile without BTF
eCapture support BTF disabled with command `make nocore` to compile at 2022/04/17. It can work normally even on Linux systems that do not support BTF.
```shell
make nocore
bin/ecapture --help
```


## Stargazers over time

[![Stargazers over time](https://starchart.cc/gojue/ecapture.svg)](https://starchart.cc/gojue/ecapture)

# Contributing
See [CONTRIBUTING](./CONTRIBUTING.md) for details on submitting patches and the contribution workflow.
