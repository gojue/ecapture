![](./images/ecapture-logo-400x400.png)
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-13-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

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

* SSL/TLS テキスト コンテキスト キャプチャ、openssl\libressl\boringssl\gnutls\nspr(nss) ライブラリのサポート。
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

### libressl & boringssl
```shell
# インストールされた libressl に対して、libssl.so.52 は動的な ssl lib です
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

## uprobe HOOK

### openssl\libressl\boringssl hook
eCapture hook `SSL_write` は、共有ライブラリ `/lib/x86_64-linux-gnu/libssl.so.1.1` の `SSL_read` 関数です。テキストコンテキストを取得し、 [eBPF maps](https://www.kernel.org/doc/html/latest/bpf/maps.html) によってユーザースペースにメッセージを送信しました。
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
hook `/bin/bash` シンボル名 `readline` です。

# コンパイル方法

Linux カーネル: >= 4.18.

## ツール
* golang 1.18 またはそれ以降
* clang 9.0 またはそれ以降
* cmake 3.18.4 またはそれ以降
* clang バックエンド: llvm 9.0 またはそれ以降
* カーネル config:CONFIG_DEBUG_INFO_BTF=y (Optional, 2022-04-17)

## コマンド
```shell
sudo apt-get update
sudo apt-get install --yes build-essential pkgconf libelf-dev llvm-9 clang-9 linux-tools-common linux-tools-generic
for tool in "clang" "llc" "llvm-strip"
do
  sudo rm -f /usr/bin/$tool
  sudo ln -s /usr/bin/$tool-9 /usr/bin/$tool
done
git clone git@github.com:gojue/ecapture.git
cd ecapture
make
bin/ecapture --help
```

## BTF なしでコンパイル
eCapture サポート BTF をコマンド `make nocore` で無効にし、2022/04/17 にコンパイルできるようにしました。
```shell
make nocore
bin/ecapture --help
```


# コントリビュート
パッチの投稿やコントリビューションのワークフローの詳細は [CONTRIBUTING](./CONTRIBUTING.md) を参照してください。

## コントリビューター

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center"><a href="https://www.cnxct.com"><img src="https://avatars.githubusercontent.com/u/709947?v=4?s=100" width="100px;" alt=""/><br /><sub><b>CFC4N</b></sub></a><br /><a href="#infra-cfc4n" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="https://github.com/gojue/ecapture/commits?author=cfc4n" title="Tests">⚠️</a> <a href="https://github.com/gojue/ecapture/commits?author=cfc4n" title="Code">💻</a></td>
      <td align="center"><a href="https://chenhengqi.com"><img src="https://avatars.githubusercontent.com/u/4277743?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Hengqi Chen</b></sub></a><br /><a href="#infra-chenhengqi" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="https://github.com/gojue/ecapture/commits?author=chenhengqi" title="Tests">⚠️</a> <a href="https://github.com/gojue/ecapture/commits?author=chenhengqi" title="Code">💻</a></td>
      <td align="center"><a href="https://chriskalix.github.io/"><img src="https://avatars.githubusercontent.com/u/46471110?v=4?s=100" width="100px;" alt=""/><br /><sub><b>chriskali</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=chriskaliX" title="Code">💻</a></td>
      <td align="center"><a href="https://github.com/huzai9527"><img src="https://avatars.githubusercontent.com/u/33509974?v=4?s=100" width="100px;" alt=""/><br /><sub><b>huzai9527</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=huzai9527" title="Code">💻</a></td>
      <td align="center"><a href="https://youtube.com/c/LinuxMonkinCloud"><img src="https://avatars.githubusercontent.com/u/3729694?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Vincent Li</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=vincentmli" title="Code">💻</a></td>
      <td align="center"><a href="http://yihong.run"><img src="https://avatars.githubusercontent.com/u/15976103?v=4?s=100" width="100px;" alt=""/><br /><sub><b>yihong</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=yihong0618" title="Code">💻</a></td>
      <td align="center"><a href="https://blaise.wang/"><img src="https://avatars.githubusercontent.com/u/9657268?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Blaise Wang</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=blaisewang" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center"><a href="https://4ft35t.github.io/"><img src="https://avatars.githubusercontent.com/u/2051049?v=4?s=100" width="100px;" alt=""/><br /><sub><b>4ft35t</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=4ft35t" title="Code">💻</a></td>
      <td align="center"><a href="https://weishu.me"><img src="https://avatars.githubusercontent.com/u/4233744?v=4?s=100" width="100px;" alt=""/><br /><sub><b>weishu</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=tiann" title="Code">💻</a></td>
      <td align="center"><a href="http://www.dashen.tech"><img src="https://avatars.githubusercontent.com/u/15921519?v=4?s=100" width="100px;" alt=""/><br /><sub><b>cui fliter</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=cuishuang" title="Code">💻</a></td>
      <td align="center"><a href="https://nfsec.pl"><img src="https://avatars.githubusercontent.com/u/15172919?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Patryk Krawaczyński</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=nfsec" title="Code">💻</a></td>
      <td align="center"><a href="https://github.com/yindex"><img src="https://avatars.githubusercontent.com/u/38709569?v=4?s=100" width="100px;" alt=""/><br /><sub><b>yindex</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=yindex" title="Code">💻</a></td>
      <td align="center"><a href="https://github.com/xujiajiadexiaokeai"><img src="https://avatars.githubusercontent.com/u/30225423?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Wenhao Jiang</b></sub></a><br /><a href="https://github.com/gojue/ecapture/commits?author=xujiajiadexiaokeai" title="Code">💻</a></td>
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
