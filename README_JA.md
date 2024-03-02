![](./images/ecapture-logo-400x400.png)

[中文介绍](./README_CN.md) | [English](./README.md) | 日本語

[![GitHub stars](https://img.shields.io/github/stars/gojue/ecapture.svg?label=Stars&logo=github)](https://github.com/gojue/ecapture)
[![GitHub forks](https://img.shields.io/github/forks/gojue/ecapture?label=Forks&logo=github)](https://github.com/gojue/ecapture)
[![CI](https://github.com/gojue/ecapture/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/gojue/ecapture/actions/workflows/code-analysis.yml)
[![Github Version](https://img.shields.io/github/v/release/gojue/ecapture?display_name=tag&include_prereleases&sort=semver)](https://github.com/gojue/ecapture/releases)

### eCapture(旁观者):  CA証明書なしで SSL/TLS のテキストコンテンツをキャプチャする eBPF を使用。

> **注**
>
> Linux/Android カーネルバージョン x86_64 4.18 以上、**aarch64 5.5** 以上に対応しています。
> Windows、macOS には対応していません。
----

# eCapture ユーザーマニュアル

![](./images/ecapture-help-v0.7.4.png)

#  eCapture の仕組み

![](./images/how-ecapture-works.png)

* SSL/TLS テキスト コンテキスト キャプチャ、openssl\libssl\boringssl\gnutls\nspr(nss) ライブラリのサポート。
* Go TLSライブラリをサポートする平文キャプチャ、つまりGolang言語で書かれたHTTPS/TLSプログラムの暗号化通信を使用します。
* bash audit, ホストセキュリティ監査用のbashコマンドをキャプチャ。
* mysql クエリ SQL 監査、サポート mysqld 5.6\5.7\8.0、および mariadDB。

# eCapture アーキテクチャ
![](./images/ecapture-architecture.png)


# はじめに

## ELF バイナリファイルを使用する

ELF zip ファイル[リリース](https://github.com/gojue/ecapture/releases)をダウンロードし、解凍して
コマンド `./ecapture --help` で使用します。

* Linux kernel version >= 4.18 is required.
* Enable BTF [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)  (Optional, 2022-04-17)

## コマンドラインオプション

> **注**
>
> ROOT 権限が必要です。
>
eCapture はデフォルトで `/etc/ld.so.conf` ファイルを検索し、
`SO` ファイルのロードディレクトリを検索し、
`openssl` シャードライブラリの場所を検索します。

ターゲットプログラムが静的にコンパイルされる場合、プログラムパスを `--libssl` フラグの値として直接設定することができます。

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
./ecapture tls -m pcap -i eth0 --pcapfile=ecapture.pcapng --port=443
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

### サーバーの BTF 設定を確認：

```shell
cfc4n@vm-server:~$# uname -r
4.18.0-305.3.1.el8.x86_64
cfc4n@vm-server:~$# cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF=y
```

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

### bash コマンド
bash コマンドをキャプチャする。
```shell
ps -ef | grep foo
```

# eBPF とは
[eBPF](https://ebpf.io)

# コンパイル方法

Linux カーネル: >= 4.18.

## ツール
* golang 1.21 またはそれ以降
* clang 9.0 またはそれ以降
* cmake 3.18.4 またはそれ以降
* clang バックエンド: llvm 9.0 またはそれ以降
* カーネル config:CONFIG_DEBUG_INFO_BTF=y (Optional, 2022-04-17)

## コマンド
### ubuntu
もしUbuntu 20.04以降を使用している場合、1つのコマンドでコンパイル環境の初期化が完了します。

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"
```
### other Linux
上記の`ツールチェーンバージョン`に列挙されたソフトウェア以外に、以下のソフトウェアも必要です。自己でインストールしてください。
* linux-tools-common
* linux-tools-generic
* pkgconf
* libelf-dev

**リポジトリのコードをクローンし、コンパイルしてください**
```shell
git clone --recurse-submodules git@github.com:gojue/ecapture.git
cd ecapture
make
bin/ecapture
```

## BTF なしでコンパイル
eCapture サポート BTF をコマンド `make nocore` で無効にし、2022/04/17 にコンパイルできるようにしました。LinuxのBTFをサポートしていなくても正常に動作することができます。
```shell
make nocore
bin/ecapture --help
```

## Stargazers over time

[![Stargazers over time](https://starchart.cc/gojue/ecapture.svg)](https://starchart.cc/gojue/ecapture)


# コントリビュート
パッチの投稿やコントリビューションのワークフローの詳細は [CONTRIBUTING](./CONTRIBUTING.md) を参照してください。
