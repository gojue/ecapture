# eCapture 远程配置修改 API

本文档介绍 **eCapture 运行过程中如何通过 HTTP 接口远程修改配置**，面向调用方（HTTP Client），说明如何构造请求和 payload 与 eCapture 通讯。

> 说明：
> - 默认监听地址：`http://127.0.0.1:28256`
> - 可通过命令行参数 `--listen` 修改监听地址，例如：`--listen 0.0.0.0:28256`
> - 所有接口均为 **HTTP POST + JSON**，路径不带前缀，直接是模块名（例如 `/tls`、`/gotls`）

---

## 1. 总体说明

### 1.1 使用场景

- 在不重启 eCapture 进程的情况下，调整各模块的抓取行为
- 通过外部管理程序、控制台、脚本，实现“点击后生效”的参数更新
- 按不同场景动态更改目标进程、端口、过滤规则等

### 1.2 基本约定

- **协议**：HTTP
- **方法**：`POST`
- **Content-Type**：`application/json`
- **请求体**：模块对应的配置 JSON（结构与 eCapture 内部 `config.*Config` 一致）
- **响应体**：统一 JSON 格式，包含状态码和模块名

---

## 2. 支持的 HTTP 路径与平台差异

eCapture 在不同平台支持的配置更新路径略有差异：

### 2.1 Linux 平台可用路径

Linux 下可以通过以下 HTTP 路径更新配置：

| 路径        | 用途简述                          |
|-------------|-----------------------------------|
| `/tls`      | OpenSSL / TLS 模块                |
| `/openssl`  | 同 `/tls`，别名                   |
| `/boringssl`| 同 `/tls`，别名                   |
| `/gotls`    | Go TLS 模块                       |
| `/gnutls`   | GnuTLS 模块                       |
| `/nss`      | NSS / NSPR 模块                   |
| `/nspr`     | 同 `/nss`，别名                   |
| `/bash`     | Bash 命令捕获（仅 Linux）         |
| `/mysqld`   | MySQLd 协议捕获（仅 Linux）       |
| `/postgress`| PostgreSQL 协议捕获（仅 Linux）   |

> 提醒：
> - `/openssl`、`/boringssl` 是 `/tls` 的别名，配置结构完全一致；
> - `/nss` 与 `/nspr` 使用同一套配置结构；
> - `/bash`、`/mysqld`、`/postgress` 在 Android GKI 平台上 **不可用**。

### 2.2 Android GKI 平台可用路径

Android GKI 下支持的路径为：

| 路径        | 用途简述                          |
|-------------|-----------------------------------|
| `/tls`      | OpenSSL / TLS 模块                |
| `/openssl`  | 同 `/tls`，别名                   |
| `/boringssl`| 同 `/tls`，别名                   |
| `/gotls`    | Go TLS 模块                       |
| `/gnutls`   | GnuTLS 模块                       |
| `/nss`      | NSS / NSPR 模块                   |
| `/nspr`     | 同 `/nss`，别名                   |

> 提醒：
> - Android 平台 **没有** `/bash`、`/mysqld`、`/postgress` 这些配置更新接口；
> - 如果你的管理程序需要同时兼容 Linux 和 Android，请在调用前根据平台做一次能力判断。

---

## 3. 通用请求与响应格式

### 3.1 请求格式

所有模块配置更新接口都使用相同的 HTTP 请求格式：

- **方法**：`POST`
- **URL**：`http://<listen-address>/<path>`  
  示例：`http://127.0.0.1:28256/tls`
- **Header**：
    - `Content-Type: application/json`
- **Body**：
    - JSON 对象，字段取决于具体模块。
    - 一般包含：
        - 通用字段：如 `pid`、`uid`、`debug`、`hex`、`btf`、`per_cpu_map_size`、`truncate_size` 等
        - 模块特有字段：如目标进程名、端口、协议相关参数等

> 配置字段请以实际版本中 `user/config/*.go` 的结构体为准，下面示例仅用于演示调用方式。

### 3.2 响应格式

所有接口的响应体为统一结构：

```json
{
  "code": 0,
  "module_type": "openssl",
  "msg": "RespOK",
  "data": null
}
```

字段说明：

- `code` (`number`)：状态码
    - `0`：成功（`RespOK`）
    - `4`：配置 JSON 解码失败（`RespConfigDecodeFailed`）
    - `5`：配置检查失败（`RespConfigCheckFailed`）
    - `6`：后台通道写入失败（`RespSendToChanFailed`）
    - 其他值：预留错误（如无效请求、内部错误等）
- `module_type` (`string`)：模块名称（如 `openssl`、`gotls`、`gnutls` 等），用于标识本次更新对应的模块
- `msg` (`string`)：`code` 对应的简短字符串，便于日志和调试
- `data`：当前接口未使用，一般为 `null`

HTTP 状态码与 `code` 的关系（调用侧可以按以下逻辑判断）：

- HTTP 200 且 `code == 0`：更新成功，后台已开始按新配置重启模块；
- HTTP 400：请求格式或配置内容不合法（`code` 通常是 4 或 5）；
- HTTP 503：eCapture 当前忙（内部配置更新通道满），可稍后重试。

---

## 4. 常用模块调用示例

下面示例都假设 eCapture 运行在本机，使用默认监听地址 `127.0.0.1:28256`。

> 注意：示例 JSON 的字段仅用于展示调用方式，不代表完整或最终字段列表，请与实际结构体对齐。

### 4.1 OpenSSL / TLS 模块（`/tls` / `/openssl` / `/boringssl`）

适用于基于 OpenSSL / BoringSSL / 通用 TLS 的应用。三个路径效果相同，可任选其一。

#### 4.1.1 使用 curl 发送配置

```bash
curl -v \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{
    "pid": 0,
    "uid": 0,
    "debug": false,
    "hex": false,
    "btf": 0,
    "per_cpu_map_size": 1024,
    "truncate_size": 0,
    "filters": {
      "target_process": ["nginx", "curl"],
      "ignore_process": ["ecapture"]
    }
  }' \
  http://127.0.0.1:28256/tls
```

可能的成功响应：

```json
{
  "code": 0,
  "module_type": "openssl",
  "msg": "RespOK",
  "data": null
}
```

#### 4.1.2 使用 Go 代码发送配置

```go
package main

import (
    "bytes"
    "encoding/json"
    "log"
    "net/http"
)

type TlsConfig struct {
    Pid           uint64 `json:"pid"`
    Uid           uint64 `json:"uid"`
    Debug         bool   `json:"debug"`
    Hex           bool   `json:"hex"`
    Btf           uint8  `json:"btf"`
    PerCpuMapSize int    `json:"per_cpu_map_size"`
    TruncateSize  uint64 `json:"truncate_size"`
    // 这里可以继续补充你真正使用的字段
}

type Resp struct {
    Code       uint8       `json:"code"`
    ModuleType string      `json:"module_type"`
    Msg        string      `json:"msg"`
    Data       interface{} `json:"data"`
}

func main() {
    cfg := TlsConfig{
        Pid:           0,
        Uid:           0,
        Debug:         false,
        Hex:           false,
        Btf:           0,
        PerCpuMapSize: 1024,
        TruncateSize:  0,
    }

    body, _ := json.Marshal(cfg)
    resp, err := http.Post(
        "http://127.0.0.1:28256/tls",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        log.Fatalf("request failed: %v", err)
    }
    defer resp.Body.Close()

    var r Resp
    if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
        log.Fatalf("decode resp failed: %v", err)
    }

    log.Printf("status=%d code=%d module=%s msg=%s",
        resp.StatusCode, r.Code, r.ModuleType, r.Msg)
}
```

---

### 4.2 GoTLS 模块（`/gotls`）

适用于 Go 程序使用的 TLS 实现。

```bash
curl -v \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{
    "pid": 0,
    "uid": 0,
    "debug": true,
    "per_cpu_map_size": 2048
  }' \
  http://127.0.0.1:28256/gotls
```

---

### 4.3 GnuTLS 模块（`/gnutls`）

适用于使用 GnuTLS 的应用程序。

```bash
curl -v \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{
    "pid": 0,
    "uid": 0,
    "debug": false
  }' \
  http://127.0.0.1:28256/gnutls
```

---

### 4.4 NSS / NSPR 模块（`/nss` / `/nspr`）

适用于基于 NSS / NSPR 的 TLS 实现（例如部分浏览器、系统组件）。

```bash
curl -v \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{
    "pid": 0,
    "uid": 0,
    "debug": false
  }' \
  http://127.0.0.1:28256/nss
```

`/nspr` 用法完全相同，只是路径不同：

```bash
curl -v \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{ ... }' \
  http://127.0.0.1:28256/nspr
```

---

### 4.5 Bash 命令捕获模块（仅 Linux：`/bash`）

> Android GKI 平台不支持此接口，如你的程序需要兼容多平台，请在调用前判断。

```bash
curl -v \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{
    "pid": 0,
    "uid": 0,
    "debug": true
  }' \
  http://127.0.0.1:28256/bash
```

---

### 4.6 MySQLd 模块（仅 Linux：`/mysqld`）

```bash
curl -v \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{
    "pid": 0,
    "uid": 0,
    "debug": false
  }' \
  http://127.0.0.1:28256/mysqld
```

---

### 4.7 PostgreSQL 模块（仅 Linux：`/postgress`）

> 注意路径拼写为 `/postgress`（双 s）。

```bash
curl -v \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{
    "pid": 0,
    "uid": 0,
    "debug": false
  }' \
  http://127.0.0.1:28256/postgress
```

---

## 5. 错误处理与重试策略

### 5.1 常见错误码

调用方可以结合 HTTP 状态码与 `code` 字段做判断：

| HTTP 状态 | `code` | 含义说明                                   | 调用方建议          |
|-----------|--------|--------------------------------------------|----------------|
| 200       | 0      | 成功，配置已被后台接受并进入重启流程       | 正常处理           |
| 200       | 1      | 请求无效                              | 请求包构建异常，修正     |
| 200       | 2      | 服务器内部错误                         | 间隔一段时间后重试              |
| 200       | 4      | JSON 解析失败（语法错误或字段类型错误）    | 修正请求体后重试       |
| 200       | 5      | 配置校验失败（必填字段缺失、值非法等）     | 根据错误日志修正配置后再发送 |
| 200       | 6      | 后台通道已满，暂时无法接受新的配置         | 间隔一段时间后重试      |
| 其他      | 1 / 2  | 无效请求 / 内部错误（当前接口不常用）      | 视情况记录日志并报警     |

更多相应码见 `cli/http/resp.go` 中的定义。

### 5.2 建议的调用模式

- 配置更新一般是管理行为，不建议高频调用；
- 对于非立即生效要求的场景，出现 `503` 时可指数退避重试；
- 在上游保留一份“上一次成功下发的配置”，发生异常时可以快速回滚。

---

## 6. 平台兼容性提醒（Linux vs Android）

- 如果你的管理程序只面向 Linux，可直接使用文中全部路径；
- 如果需要同时兼容 Linux 和 Android GKI，建议：
    1. 通过命令行参数、环境变量或探测接口确认当前运行平台；
    2. 对 `bash` / `mysqld` / `postgress` 等 **仅 Linux 支持** 的路径做条件调用；
    3. TLS / GoTLS / GnuTLS / NSS 相关路径两端一致，可通用。

---

## 7. 版本与字段对齐建议

- 不同版本的 eCapture，`user/config/*.go` 中的字段可能会有微调；
- 推荐做法：
    - 在你的项目中定义与 eCapture 相同的配置结构（同名字段 / 同类型）；
    - 或直接使用 JSON 动态对象，只填你实际需要控制的字段，其余使用默认值；
    - 如需对接多版本，可通过 eCapture 的版本信息自行做兼容处理。

---

## 8. 变更历史

| 版本  | 日期       | 说明                               |
|-------|------------|------------------------------------|
| 0.1.0 | 2025-12-07 | 初版：远程配置修改 HTTP API 说明   |