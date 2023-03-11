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

#  eCapture の仕組み

![](./images/how-ecapture-works.png)

* SSL/TLS テキスト コンテキスト キャプチャ、openssl\libssl\boringssl\gnutls\nspr(nss) ライブラリのサポート。
* Go TLSライブラリをサポートする平文キャプチャ、つまりGolang言語で書かれたHTTPS/TLSプログラムの暗号化通信を使用します。
* bash audit, ホストセキュリティ監査用のbashコマンドをキャプチャ。
* mysql クエリ SQL 監査、サポート mysqld 5.6\5.7\8.0、および mariadDB。

# eCapture アーキテクチャ
![](./images/ecapture-architecture.png)

# eCapture ユーザーマニュアル

[![eCapture User Manual](./images/ecapture-user-manual.png)](https://www.youtube.com/watch?v=CoDIjEQCvvA "eCapture User Manual")

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

### Pcapng 結果

`./ecapture tls -i eth0 -w pcapng -p 443` 平文パケットをキャプチャして pcapng ファイルとして保存し、 `Wireshark`
 でそれを直接読みます。

### 平文結果

`./ecapture tls` はすべてのプレーンテキストのコンテキストをキャプチャしてコンソールに出力し、`openssl TLS` の `Master Secret` をキャプチャして 
`ecapture_masterkey.log` に保存することができます。また、`tcpdump` を使って生のパケットをキャプチャし、
`Wireshark` を使って `Master Secret` 設定でそれらを読み込むことができます。

>

### サーバーの BTF 設定を確認：

```shell
cfc4n@vm-server:~$# uname -r
4.18.0-305.3.1.el8.x86_64
cfc4n@vm-server:~$# cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF=y
```

### tls コマンド

TLS テキストコンテキストをキャプチャします。
ステップ 1:
```shell
./ecapture tls --hex
```

ステップ 2:
```shell
curl https://github.com
```

### libssl & boringssl
```shell
# インストールされた libssl に対して、libssl.so.52 は動的な ssl lib です
vm@vm-server:~$ ldd /usr/local/bin/openssl
	linux-vdso.so.1 (0x00007ffc82985000)
	libssl.so.52 => /usr/local/lib/libssl.so.52 (0x00007f1730f9f000)
	libcrypto.so.49 => /usr/local/lib/libcrypto.so.49 (0x00007f1730d8a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1730b62000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f17310b2000)

# libssl を使って libssl.so のパスを設定
vm@vm-server:~$ sudo ./ecapture tls --libssl="/usr/local/lib/libssl.so.52" --hex

# 別の端末で実行し、何らかの文字列を入力し、ecapture の出力を確認
vm@vm-server:~$ /usr/local/bin/openssl s_client -connect github.com:443

# インストールされた boringssl の場合、使い方は同じです
/path/to/bin/bssl s_client -connect github.com:443
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
* golang 1.18 またはそれ以降
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
git clone git@github.com:gojue/ecapture.git
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


# コントリビュート
パッチの投稿やコントリビューションのワークフローの詳細は [CONTRIBUTING](./CONTRIBUTING.md) を参照してください。
