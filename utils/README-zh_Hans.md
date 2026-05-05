# utils — 结构体偏移地址生成脚本

本目录包含用于生成 eBPF 兼容 C 头文件的工具集
（`kern/boringssl_a_XX_kern.c`、`kern/boringssl_na_kern.c`、`kern/gnutls_*.c`、
`kern/openssl_*.c` 等）。每个头文件定义了 TLS 关键字段在目标库内部结构体中的字节偏移地址常量（`#define`），eBPF 探针在运行时通过这些常量从进程内存中读取明文密钥。

---

## 目录结构

```
utils/
├── boringssl-offset.c              # C++17 偏移探测工具（Android BoringSSL 专用）
├── boringssl_android_offset.sh     # 驱动脚本：Android 13–16 BoringSSL
├── boringssl_non_android_offset.sh # 驱动脚本：非 Android（上游）BoringSSL
├── gnutls_offset.c / gnutls_offset.sh
├── openssl_*_offset.c / openssl_offset_*.sh
└── README-zh_Hans.md               # 本文件
```

---

## 快速开始

所有脚本**必须在项目根目录**（包含 `go.mod` 的目录）下执行：

```bash
# Android BoringSSL（android13 – android16）
bash utils/boringssl_android_offset.sh

# 非 Android（上游）BoringSSL
bash utils/boringssl_non_android_offset.sh

# GnuTLS
bash utils/gnutls_offset.sh

# OpenSSL（选择对应版本的脚本）
bash utils/openssl_offset_3.5.sh
```

生成的文件写入 `kern/` 目录。若目标文件已存在，脚本会跳过该版本。删除文件可强制重新生成。

> **平台要求**：脚本需要编译原生 C++ 代码，必须在 Linux / Android 构建主机上运行
> （x86\_64 内核 ≥ 4.18，aarch64 ≥ 5.5），**不支持 macOS**。
> 请通过 SSH 登录远程 Linux 服务器执行：
> ```bash
> ssh cfc4n@172.16.71.128
> cd /home/cfc4n/project/ecapture
> bash utils/boringssl_android_offset.sh
> ```

---

## `boringssl_android_offset.sh` 工作原理

### 流程概览

```
boringssl_android_offset.sh
        │
        ├─ git clone / checkout  android13-release … android16-release
        │
        ├─ 编译  boringssl-offset.c  （C++17，链接 boringssl 头文件）
        │
        ├─ 运行 ./offset  →  输出 #define 常量 + feature-flag 宏
        │
        └─ 包装输出  →  kern/boringssl_a_XX_kern.c
```

### 添加新 Android 版本

在 `boringssl_android_offset.sh` 的 `sslVerMap` 中加一行：

```bash
sslVerMap["5"]="17"   # android17-release
```

重新运行脚本即可，大多数情况下无需其他改动——详见下方[设计思路](#boringssl-offsetc--偏移探测工具)。

---

## `boringssl-offset.c` — 偏移探测工具

### 用途

该工具**针对目标库自身的头文件编译**，因此 `offsetof(struct_name, field)` 返回的是该特定库版本与 CPU 架构下的精确字节偏移。

输出示例：

```c
// ssl_st->session
#define SSL_ST_SESSION 0x58

// ssl_session_st->ssl_version
#define SSL_SESSION_ST_SSL_VERSION 0x4
```

这些 `#define` 值原样写入生成的 kern 头文件，在 eBPF 编译阶段被 `kern/boringssl_masterkey.h` 使用。

### 设计思路 — 基于 C++17 类型特征的自动版本探测

旧版工具使用固定的字段列表，依赖 shell 脚本中的 `sed` 后处理来应对不同 Android 版本间被删除或重命名的字段。这种方式很脆弱：每当新 Android 版本改动了某个结构体，就需要在脚本里增加一条专用的 `sed` 规则。

当前工具改用 **C++17 类型特征（`std::void_t` + SFINAE）** 在编译期探测字段是否可访问，再通过**偏模板特化（partial template specialisation）** 选择正确的输出路径：

```
                  字段是否存在？
                  ┌─── 存在 ──→  输出 offsetof(T, field) 的值
 类型特征探测 ────┤
                  └─── 不存在 ──→  输出替代宏 / 哨兵值
```

#### 关键设计原则

1. **不使用 `if constexpr`**。在非模板函数中，`if constexpr` 的两个分支仍然都会被编译器进行语法检查，因此即使在未执行的分支中，`offsetof(T, 已删除字段)` 也会触发硬错误。

2. **使用偏模板特化**。`emit_foo<T, true>::emit()` 的函数体中包含 `offsetof(T, field)` 这一**依赖表达式**（依赖于模板参数 `T`），编译器只有在该特化被实际实例化时才会检查它——即只有在选择 `Present=true` 分支时才会编译。

3. **feature-flag 宏是探测的副产品**。当某个字段不存在时，工具会输出一个**替代宏**，该宏的存在本身就是一个版本特性标志，供下游消费者判断：

   | 不存在的字段 | 输出的宏 | 消费方 |
   |---|---|---|
   | `ssl_st::version` | `SSL_SESSION_ST_SSL_VERSION` | `boringssl_const.h`、`boringssl_masterkey.h` |
   | `ssl_session_st::secret_length` | `SSL_SESSION_ST_SECRET_LENGTH 0xFF`（哨兵） | `boringssl_masterkey.h` |
   | `SSL3_STATE::version`（存在时） | `BSSL__SSL3_STATE_VERSION` | `boringssl_masterkey.h` |

### 已跟踪的字段变化

| Android 版本 | 变化 | 工具行为 |
|---|---|---|
| ≤ 15 | `ssl_st::version` 存在 | 输出 `SSL_ST_VERSION` |
| 16+ | `ssl_st::version` **被删除** | 输出 `SSL_SESSION_ST_SSL_VERSION`（feature flag） |
| ≤ 15 | `ssl_session_st::secret_length` 存在 | 输出 `SSL_SESSION_ST_SECRET_LENGTH <偏移值>` |
| 16+ | `ssl_session_st::secret_length` **被删除** | 输出 `SSL_SESSION_ST_SECRET_LENGTH 0xFF`（哨兵） |
| ≤ 15 | `SSL3_STATE::version` 不存在 | 不输出任何内容 |
| 16+ | `SSL3_STATE::version` **新增** | 输出 `BSSL__SSL3_STATE_VERSION`（feature flag） |

### 支持未来新版本 Android 的步骤

若新版 Android 删除或改动了某个结构体字段：

1. **在 `boringssl-offset.c` 中添加类型特征探测**：
   ```cpp
   template <typename T, typename = void>
   struct foo_has_new_field : std::false_type {};
   template <typename T>
   struct foo_has_new_field<T, std::void_t<decltype(std::declval<T>().new_field)>>
       : std::true_type {};
   ```

2. **添加一对 emitter**（主模板 + `<T,true>` 偏特化）：
   ```cpp
   template <typename T, bool Present>
   struct emit_new_field {
       static void emit() { /* 字段不存在：输出替代宏 */ }
   };
   template <typename T>
   struct emit_new_field<T, true> {
       static void emit() { format("foo", "new_field", offsetof(T, new_field)); }
   };
   ```

3. **在 `main()` 中调用 emitter**：
   ```cpp
   emit_new_field<foo_t, foo_has_new_field<foo_t>::value>::emit();
   ```

4. **在 `boringssl_const.h` 或 `boringssl_masterkey.h` 中处理 feature flag**：
   ```c
   #ifdef NEW_FEATURE_FLAG
   // 新版本特有逻辑
   #endif
   ```

5. **在 `boringssl_android_offset.sh` 中注册新版本**：
   ```bash
   sslVerMap["5"]="17"   # android17-release
   ```

全程无需 `sed` 规则，工具本身不包含任何硬编码的版本号判断。

---

## `boringssl_const.h` 与 `boringssl_masterkey.h` — 自适应头文件

这两个头文件已将**所有版本特定逻辑实现为纯 C 预处理器条件编译**，只要偏移工具输出了正确的 feature flag，就无需手动修改。

### `boringssl_const.h` — TLS 1.3 密钥偏移地址

通过 `#ifdef SSL_SESSION_ST_SSL_VERSION`（Android 16+ feature flag）在两套偏移计算公式间切换，用于 `SSL_HANDSHAKE` 结构体中 TLS 1.3 密钥字段：

| | Android ≤ 15 | Android 16+ |
|---|---|---|
| 密钥存储类型 | `private uint8_t secret_[48]`（私有 raw 数组） | `public InplaceVector<uint8_t,48>`（公有） |
| 字段步长 | 48 字节 | 49 字节（`SSL_HANDSHAKE_FIELD_STEP`） |
| `SSL_HANDSHAKE_SECRET_` 基址 | `roundup(MAX_VERSION+2, 8) + 8` | `MAX_VERSION + 2` |
| `SSL_HANDSHAKE_HASH_LEN_` | 独立的 `size_t hash_len_` 字段 | `secret.size_`，位于 `SECRET_ + 48` |

6 个下游字段偏移（`EARLY_TRAFFIC_SECRET_` 等）统一用 `SECRET_ + FIELD_STEP * N` 一条公式计算，无重复代码。

### `boringssl_masterkey.h` — TLS 版本探测

使用两个 feature flag 确保在所有 Android 版本上正确工作：

- `#ifndef SSL_SESSION_ST_SSL_VERSION` — Android ≤ 15：从 `ssl_st.version` 读取 TLS 版本。
- `#ifdef BSSL__SSL3_STATE_VERSION` — Android 16+：在 TLS 1.2 / 1.3 分支判断**之前**，从 `SSL3_STATE.version`（偏移 `0xd0`）读取版本，确保 TLS 1.3 连接被正确识别、密钥被正确捕获。
- `#ifdef SSL_SESSION_ST_SSL_VERSION` — 在 TLS 1.2 分支内部，从 `ssl_session_st.ssl_version` 补读版本，用于准确上报。

#### Android 16 的背景

Android 16 对 BoringSSL 做了较大重构，主要影响：

| 变化 | 影响 |
|---|---|
| `ssl_st.version` 字段删除 | 无法直接从 SSL 对象读取协议版本 |
| `ssl_session_st.secret_length` 字段删除 | master secret 长度需用最大值（48）替代 |
| `ssl_session_st.secret` 类型从 `uint8_t[]` 改为 `InplaceVector<uint8_t,48>` | 偏移值不变（`storage_` 在首位），但 TLS 1.3 所有握手密钥字段同样改为 InplaceVector |
| `SSL_HANDSHAKE` TLS 1.3 密钥从 `private uint8_t[]` 改为 `public InplaceVector` | 字段步长从 48 变为 49，整体基址前移 8 字节 |
| `SSL3_STATE.version` 新增 | 替代被删除的 `ssl_st.version`，用于读取协议版本 |

---

## 注意事项

- **网络访问**：启动时会尝试 `git fetch --tags`；若网络不可用，脚本会使用本地已缓存的分支继续执行。
- **CPU 架构**：偏移地址与 CPU 架构强相关。工具必须在**与目标设备相同的 CPU 架构**上编译并运行（例如，为 Android ARM64 设备生成偏移时须在 aarch64 主机上运行），跨架构生成会得到错误的偏移值。
- **不要手动编辑生成文件**：脚本不再在工具输出之后追加任何硬编码的 `#define`，所有常量均由工具统一输出。手动修改生成文件会导致与源码漂移，应重新运行脚本生成。
- **`boringssl-offset.c` 需要 C++17**：`std::void_t` 依赖 C++17 标准，编译时必须传入 `-std=c++17`，脚本已自动添加该参数。

