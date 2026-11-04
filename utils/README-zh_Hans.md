# TLS 结构体偏移工具

这些工具针对 TLS 库的内部头文件编译，输出 eCapture eBPF 探针所需的字段偏移。
`kern/` 中按版本区分的文件是源码输入，不是可以随意清理的构建产物。

库版本映射、资产变体和验证要求见 [探针开发指南](../docs/agent/probe-development.md)。
[English](README.md)

## 工具分工

| 文件 | 用途 |
| --- | --- |
| `boringssl_android_offset.sh`、`boringssl-offset.c` | Android 13–17 BoringSSL 偏移 |
| `boringssl_non_android_offset.sh`、`boringssl-offset.c` | 上游 BoringSSL 偏移 |
| `gnutls_offset.sh`、`gnutls_offset.c` | 从已配置源码生成版本化 GnuTLS 偏移 |
| `openssl_offset_*.sh`、`openssl_*_offset.c` | OpenSSL 1.0.2、1.1.0、1.1.1、3.x、4.0 的版本映射 |
| `protobuf_visualizer/` | 独立的 WebSocket/Protobuf [调试客户端](protobuf_visualizer/README_CN.md) |

## 运行方式

偏移工具的编译和执行必须在 Linux 上进行，Android 目标也使用 Linux 构建主机。
测量得到的布局必须匹配目标库的版本、构建配置和 CPU ABI，不能假定不同架构的
偏移相同。支持的执行环境见 [构建指南](../docs/agent/build-test.md)。

在仓库根目录执行：

```bash
bash utils/boringssl_android_offset.sh
bash utils/boringssl_non_android_offset.sh
bash utils/openssl_offset_3.5.sh
bash utils/gnutls_offset.sh 3.8.11
```

OpenSSL/BoringSSL 脚本将库源码获取到 `deps/`，切换到映射的版本，编译偏移工具，
再写入 `kern/` 中的对应文件。已有输出会被跳过。需要重新生成已跟踪文件以比较
布局时，使用独立检出目录，并在采用前审查差异。

脚本的版本表可能将多个库版本映射到同一资产；即使流程相似，也要保留这些映射。
生成偏移文件不等于新增运行时支持：必要时还须更新 Go 选择器和构建目标，并针对
真实库验证 CO-RE 与 non-CO-RE 两种资产。

## BoringSSL 字段探测

`boringssl-offset.c` 需要 C++17。它用 `std::void_t` 和偏模板特化选择字段存在时
才实例化的 emitter，使 `offsetof(T, field)` 保持为依赖表达式，避免编译不存在的
字段。非模板函数中的 `if constexpr` 不能替代此模式。

生成的宏由 [`boringssl_const.h`](../kern/boringssl_const.h) 和
[`boringssl_masterkey.h`](../kern/boringssl_masterkey.h) 使用：

| 布局变化 | 工具与消费方的约定 |
| --- | --- |
| Android 16+ 缺少 `ssl_st::version` | 输出 `SSL_SESSION_ST_SSL_VERSION`，选择另一条版本和布局处理路径 |
| 缺少 `ssl_session_st::secret_length` | 输出 `0xFF` 哨兵，表示使用最大 master-secret 长度 |
| 存在 `SSL3_STATE::version` | 输出 `BSSL__SSL3_STATE_VERSION`，用于协议版本判断 |
| `SSL3_STATE` 的流量密钥向量公开 | 输出读写存储及长度偏移，并按端点角色选择 client/server 标签 |
| Android 17 将 `ssl_cipher_st::id` 重命名 | 从 `protocol_id` 输出 `SSL_CIPHER_ST_ID` |

TLS 1.3 握手密钥的字段间隔由 `boringssl_const.h` 推导：原始数组使用 48 字节步长，
对应的 `InplaceVector` 布局使用 49 字节步长。遇到新布局时，应补充探测器、emitter
和消费逻辑，再更新 Android 驱动脚本的版本表并验证，不要直接手改偏移常量。

Android 驱动在 `git fetch --tags` 失败后可以使用缓存分支继续执行。需要记录实际
使用的源码提交；缓存回退并不能证明本地源码已对应新版发布。

## GnuTLS 源码身份与布局比较

`gnutls_offset.sh` 接受 `3.8.0` 至 `3.8.13` 范围内的一个或多个版本；不传参数时
遍历整个范围。可生成的版本范围与运行时支持的版本映射是两回事。默认编译器为
`clang`，可通过 `CC` 覆盖。

用独立输出目录比较重新生成的偏移：

```bash
GNUTLS_OUTPUT_DIR=/tmp/ecapture-gnutls-offsets \
  bash utils/gnutls_offset.sh 3.8.11
```

脚本默认克隆并配置指定的上游版本。对于含发行版补丁的库，传入已配置的源码目录
及准确的源码身份；这种形式只接受一个版本：

```bash
GNUTLS_SOURCE_DIR=/path/to/configured/gnutls \
GNUTLS_SOURCE_ID='<full-git-commit-or-release-archive-sha256>' \
GNUTLS_OUTPUT_DIR=/tmp/ecapture-gnutls-offsets \
  bash utils/gnutls_offset.sh 3.8.11
```

执行前替换尖括号占位符。脚本会核对 `config.h` 中的版本，并在输出文件中记录
源码身份和 `config.h` 的 SHA256；配置或编译失败不会发布输出。准备源码时，应
保留目标库实际使用的构建选项及发行版补丁。
