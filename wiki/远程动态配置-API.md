# 远程动态配置 API

## 概述

eCapture 支持在运行时通过 HTTP 接口热更新配置，无需重启进程即可调整各模块的抓取行为。此功能默认禁用，需要通过 `--listen` 参数启用。

## 启用方式

```bash
# 启用 HTTP 配置服务（默认地址）
sudo ecapture tls --listen 127.0.0.1:28256

# 显式禁用
sudo ecapture tls --listen ""
```

## 基本约定

- **协议**：HTTP
- **方法**：`POST`
- **Content-Type**：`application/json`
- **请求体**：模块对应的配置 JSON
- **响应体**：统一 JSON 格式

## 支持的路径

### Linux 平台

| 路径 | 用途 |
|------|------|
| `/tls` | OpenSSL / TLS 模块 |
| `/openssl` | `/tls` 的别名 |
| `/boringssl` | `/tls` 的别名 |
| `/gotls` | Go TLS 模块 |
| `/gnutls` | GnuTLS 模块 |
| `/nss` | NSS / NSPR 模块 |
| `/nspr` | `/nss` 的别名 |
| `/bash` | Bash 命令捕获 |
| `/mysqld` | MySQL 协议捕获 |
| `/postgress` | PostgreSQL 协议捕获 |

### Android GKI 平台

Android 平台**不支持** `/bash`、`/mysqld`、`/postgress` 路径，其他路径与 Linux 一致。

## 请求格式

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
    "truncate_size": 0
  }' \
  http://127.0.0.1:28256/tls
```

### 通用字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `pid` | uint64 | 目标进程 PID（0 = 所有进程） |
| `uid` | uint64 | 目标用户 UID（0 = 所有用户） |
| `debug` | bool | 调试模式 |
| `hex` | bool | 十六进制输出 |
| `btf` | uint8 | BTF 模式 |
| `per_cpu_map_size` | int | eBPF map 每 CPU 大小 |
| `truncate_size` | uint64 | 截断大小 |

## 响应格式

```json
{
  "code": 0,
  "module_type": "openssl",
  "msg": "RespOK",
  "data": null
}
```

### 状态码

| code | 含义 | HTTP 状态码 |
|------|------|------------|
| 0 | 成功（RespOK） | 200 |
| 4 | 配置 JSON 解码失败 | 400 |
| 5 | 配置检查失败 | 400 |
| 6 | 后台通道写入失败 | 503 |

## 使用场景

1. **无需重启动态调整**：运行过程中切换目标进程、修改过滤规则
2. **外部管理集成**：通过管理控制台或脚本发送 HTTP 请求控制 eCapture
3. **自动化运维**：与 Ansible/Salt 等运维工具集成，批量管理多台主机的 eCapture 配置

## Go 代码调用示例

```go
package main

import (
    "bytes"
    "encoding/json"
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
}

func main() {
    cfg := TlsConfig{Pid: 12345, PerCpuMapSize: 1024}
    body, _ := json.Marshal(cfg)
    http.Post("http://127.0.0.1:28256/tls", "application/json", bytes.NewReader(body))
}
```

## 源码参考

| 组件 | 路径 |
|------|------|
| HTTP 服务实现 | `cli/http/` |
| API 文档 | `docs/remote-config-update-api-zh_Hans.md` |
| 各探针配置结构体 | `internal/config/` |
