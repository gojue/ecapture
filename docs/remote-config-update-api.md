# eCapture Remote Configuration Update API

This document describes how to update eCapture’s runtime configuration via HTTP, **from the client side**.  
It focuses on how to construct HTTP requests and JSON payloads to communicate with eCapture.

> Notes:
> - Default listen address: `http://127.0.0.1:28256`
> - You can change it via CLI flag `--listen`, for example: `--listen 0.0.0.0:28256`
> - All endpoints are **HTTP POST + JSON**
> - Endpoint paths have **no prefix**. They are just the module names (e.g. `/tls`, `/gotls`, `/gnutls`).

---

## 1. Overview

### 1.1 Use cases

- Adjust capture behavior **without restarting** the eCapture process
- Build an external management tool / control panel / script that can “update and apply configuration” on demand
- Dynamically change target processes, ports, filters, and other runtime parameters

### 1.2 Basic rules

- **Protocol**: HTTP
- **HTTP method**: `POST`
- **Content-Type**: `application/json`
- **Request body**: JSON configuration object for the target module  
  (same structure as the corresponding `config.*Config` type inside eCapture)
- **Response body**: a unified JSON structure with status code and module name

---

## 2. Supported HTTP paths and platform differences

The set of supported configuration update paths is slightly different between Linux and Android GKI.

### 2.1 Linux paths

On Linux, you can update configurations via the following HTTP paths:

| Path         | Description                                    |
|--------------|------------------------------------------------|
| `/tls`       | OpenSSL / TLS module                           |
| `/openssl`   | Alias of `/tls`                                |
| `/boringssl` | Alias of `/tls`                                |
| `/gotls`     | Go TLS module                                  |
| `/gnutls`    | GnuTLS module                                  |
| `/nss`       | NSS / NSPR module                              |
| `/nspr`      | Alias of `/nss`                                |
| `/bash`      | Bash command capture (Linux only)              |
| `/mysqld`    | MySQLd protocol capture (Linux only)           |
| `/postgress` | PostgreSQL protocol capture (Linux only, note the spelling) |

> Reminder:
> - `/openssl` and `/boringssl` are aliases of `/tls`; they share the same configuration structure.
> - `/nss` and `/nspr` share the same configuration structure.
> - `/bash`, `/mysqld`, and `/postgress` do **not** exist on Android GKI.

### 2.2 Android GKI paths

On Android GKI, the available paths are:

| Path         | Description                                    |
|--------------|------------------------------------------------|
| `/tls`       | OpenSSL / TLS module                           |
| `/openssl`   | Alias of `/tls`                                |
| `/boringssl` | Alias of `/tls`                                |
| `/gotls`     | Go TLS module                                  |
| `/gnutls`    | GnuTLS module                                  |
| `/nss`       | NSS / NSPR module                              |
| `/nspr`      | Alias of `/nss`                                |

> Reminder:
> - Android GKI does **not** expose `/bash`, `/mysqld`, `/postgress` configuration endpoints.
> - If your management client needs to support both Linux and Android, detect the platform and only call supported paths.

---

## 3. Common request and response format

### 3.1 Request format

All configuration update endpoints use the same HTTP request pattern:

- **Method**: `POST`
- **URL**: `http://<listen-address>/<path>`  
  Example: `http://127.0.0.1:28256/tls`
- **Headers**:
    - `Content-Type: application/json`
- **Body**:
    - JSON object. Its fields depend on the specific module.
    - Typically includes:
        - Common fields: `pid`, `uid`, `debug`, `hex`, `btf`, `per_cpu_map_size`, `truncate_size`, etc.
        - Module-specific fields: target process names, ports, protocol-related options, and so on.

> Exact field names and types are defined in `user/config/*.go`.  
> Examples below are illustrative only, to show how to call the API from the client side.

### 3.2 Response format

All endpoints return a unified JSON structure:

```json
{
  "code": 0,
  "module_type": "openssl",
  "msg": "RespOK",
  "data": null
}
```

Field description:

- `code` (`number`): status code
    - `0` – success (`RespOK`)
    - `4` – configuration JSON decode failed (`RespConfigDecodeFailed`)
    - `5` – configuration check failed (`RespConfigCheckFailed`)
    - `6` – failed to send configuration into internal channel (`RespSendToChanFailed`)
    - other values – reserved (e.g. invalid request, internal server error)
- `module_type` (`string`): module identifier for this update (e.g. `openssl`, `gotls`, `gnutls`)
- `msg` (`string`): human-readable string corresponding to `code`, useful for logging and debugging
- `data`: currently unused and usually `null`

Relationship between HTTP status and `code` (for clients):

- HTTP 200 + `code == 0`:  
  Configuration accepted. eCapture has begun applying the new config (by restarting the module internally).
- HTTP 400:  
  Request format or config content is invalid (`code` usually 4 or 5).
- HTTP 503:  
  eCapture is currently busy and cannot accept new config updates (`code` is 6). You can retry later.

---

## 4. Typical module calls

All examples assume eCapture is running on the local machine with the default address `127.0.0.1:28256`.

> Again, JSON fields below are **examples only**.  
> Align them with the actual fields from your current `user/config/*.go`.

### 4.1 OpenSSL / TLS module (`/tls` / `/openssl` / `/boringssl`)

Used for applications based on OpenSSL / BoringSSL / generic TLS.  
The three paths are equivalent; you can pick any of them.

#### 4.1.1 Using curl

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

A typical success response:

```json
{
  "code": 0,
  "module_type": "openssl",
  "msg": "RespOK",
  "data": null
}
```

#### 4.1.2 Using Go

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
    // Add real TLS config fields here to match user/config/OpensslConfig
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

### 4.2 GoTLS module (`/gotls`)

Used for Go applications that use the Go TLS stack.

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

### 4.3 GnuTLS module (`/gnutls`)

Used for applications that rely on GnuTLS.

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

### 4.4 NSS / NSPR module (`/nss` / `/nspr`)

Used for modules based on NSS / NSPR (e.g. some browsers or system components).

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

`/nspr` is identical, only the path changes:

```bash
curl -v \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{ ... }' \
  http://127.0.0.1:28256/nspr
```

---

### 4.5 Bash command capture module (Linux only: `/bash`)

> Not available on Android GKI.  
> If your management tool targets multiple platforms, detect the platform before calling this endpoint.

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

### 4.6 MySQLd module (Linux only: `/mysqld`)

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

### 4.7 PostgreSQL module (Linux only: `/postgress`)

> The path is spelled `/postgress` with a double “s”.

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

## 5. Error handling and retry strategy

### 5.1 Common status codes

You can combine HTTP status and the `code` field from the JSON response:

| HTTP status | `code` | Meaning                                            | Client suggestion                          |
|-------------|--------|----------------------------------------------------|--------------------------------------------|
| 200         | 0      | Success, configuration accepted and applied       | Normal flow                                |
| 200         | 4      | JSON decode failed (syntax error / type mismatch) | Fix request body and retry                 |
| 200         | 5      | Config check failed (missing field, invalid value)| Fix config content based on logs and retry |
| 200         | 6      | Internal update channel is full / busy            | Wait and retry later                       |
| 200         | 1 / 2  | Invalid request / internal server error           | Log and alert as needed                    |

### 5.2 Recommended calling pattern

- Configuration updates are management operations; they should not be called at high frequency.
- When you see HTTP 503 with `code == 6`:
    - Use a backoff strategy (e.g. exponential backoff) and retry later.
- On the caller side, keep a copy of the **last known-good config**:
    - If a new config causes unexpected behavior, you can quickly rollback by posting the previous config again.

---

## 6. Platform compatibility (Linux vs Android)

- If your tool only targets Linux, you can use all paths listed for Linux.
- If your tool must work on both Linux and Android GKI:
    1. Determine the platform using CLI flags, environment variables, or your own detection mechanism.
    2. Only call `/bash`, `/mysqld`, `/postgress` on Linux, because they do not exist on Android.
    3. TLS / GoTLS / GnuTLS / NSS paths are shared and can be used on both platforms.

---

## 7. Versioning and field alignment

- Different eCapture versions may slightly change config structures in `user/config/*.go`.
- Recommended approach:
    - In your client code, define config structs that mirror the current eCapture version (field names and types match).
    - Or use dynamic JSON (e.g. `map[string]any`) and only fill fields that you really need.
    - If you need to support multiple eCapture versions, build your own compatibility layer (e.g. version negotiation or feature flags).

---

## 8. Changelog

| Version | Date       | Description                                   |
|---------|------------|-----------------------------------------------|
| 0.1.0   | 2025-12-07 | Initial version of the remote config API doc |
