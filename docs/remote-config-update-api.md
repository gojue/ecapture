# Runtime configuration HTTP API

[中文](remote-config-update-api-zh_Hans.md)

The API restarts the running probe with a new configuration. Enable it
explicitly when starting eCapture; `--listen` is empty/disabled by default:

```bash
sudo ./bin/ecapture tls --listen=127.0.0.1:28256 \
  --eventaddr=/tmp/events.txt
```

Requests are `POST` with `Content-Type: application/json`. The built-in HTTP
server has no application authentication or TLS; the example binds loopback.
It is independent of the `--ecaptureq` event listener.

## Scope and endpoints

Send updates for the **same probe type** that was selected at process startup.
For example, a process started with `tls` accepts TLS configuration through
`/tls`, `/openssl`, or `/boringssl`. The runtime retains the original factory
probe type; this is not a cross-probe hot-swap API. A wrong-probe request is
not a supported way to switch modules and may fail during reinitialization.

| POST path | Configuration type | Linux | Android build |
| --- | --- | --- | --- |
| `/tls`, `/openssl`, `/boringssl` | OpenSSL/BoringSSL | Yes | Yes |
| `/gotls` | GoTLS | Yes | Yes |
| `/bash` | Bash | Yes | Yes |
| `/gnutls` | GnuTLS | Yes | Unsupported |
| `/nss`, `/nspr` | NSPR/NSS | Yes | Unsupported |
| `/mysqld` | MySQL | Yes | Unsupported |
| `/postgres`, `/postgress` | PostgreSQL | Yes | Unsupported |

Both platforms register these routes. Unsupported Android configuration
factories return HTTP 400 with `code: 4`; their routes are not absent.
There is currently no `/zsh` route. `/postgress` remains a compatibility alias.
Platform availability does not remove each probe's binary/library requirements.

## Configuration replacement and inheritance

The server decodes into a **fresh module configuration**, then validates and
applies it. This is not a general JSON patch over the running configuration.
Only these three fields inherit from the active generation when omitted:

| JSON field | Meaning | Explicit value |
| --- | --- | --- |
| `event_collector_addr` | Primary captured-event destination | `""` explicitly clears it before mode-specific normalization |
| `event_rotate_size_mb` | File rotation size | `0` disables this rotation threshold |
| `event_rotate_seconds` | File rotation interval | `0` disables this rotation threshold |

Other omitted common and module-specific fields use constructor defaults or
zero values, not the active values. Resend the library/ELF path, mode, filters,
and other settings you need to retain. CLI flags and JSON field names differ.
Unknown JSON fields are generally ignored by the current decoder, so a typo
can silently leave a default in effect.

An empty event destination becomes stdout in text mode; keylog/pcapng still
require a destination after normalization, possibly supplied by their legacy
file field. Rotation is only valid for file-backed text/keylog output. When
changing a rotating file destination to a network sink, explicitly set both
rotation fields to zero to avoid inheriting invalid settings.

Operational logging and typed eCaptureQ publication are process-lifetime
dependencies and are reattached to the new probe. This API does not change
`--logaddr`, `--ecaptureq`, or the HTTP listening address.

## Request fields

Common fields are defined in [BaseConfig](../internal/config/base_config.go)
and [CommonConfigPatch](../internal/config/common.go):

| JSON field | Type | Notes |
| --- | --- | --- |
| `pid`, `uid` | unsigned integer | Process/user filters; `0` means no such filter |
| `debug`, `is_hex` | boolean | Probe debug and hex representation settings |
| `btf_mode` | unsigned integer | `0` auto, `1` CO-RE, `2` non-CO-RE; must be supported by embedded assets |
| `per_cpu_map_size` | integer | Positive buffer size in **bytes**; CLI `--mapsize` is in pages |
| `event_collector_addr` | string | stdout, file/path, TCP or WebSocket destination |
| `event_rotate_size_mb`, `event_rotate_seconds` | unsigned 16-bit integer | File rotation settings |
| `cgroup_path` | string | cgroup filter where supported by the probe |
| `perf_reorder`, `perf_reorder_lag_ms` | boolean, unsigned integer | Reordering where supported by the probe/event reader |

`byte_code_file_mode` must match the binary's embedded asset mode; normally
leave it at the factory default. `truncate_size` is serialized but has no
current production consumer, so do not rely on it to limit output.

Frequently used module fields:

| Probe | JSON field names | Definition |
| --- | --- | --- |
| OpenSSL/BoringSSL | `opensslpath`, `capturemode`, `text_source`, `keylogfile`, `pcapfile`, `ifname`, `pcapfilter` | [config.go](../internal/probe/openssl/config.go) |
| GoTLS | `elf_path`, `capture_mode`, `text_source`, `keylog_file`, `pcap_file`, `ifname`, `pcap_filter` | [config.go](../internal/probe/gotls/config.go) |
| GnuTLS | `gnutlspath`, `capturemode`, `text_source`, `keylogfile`, `pcapfile`, `ifname`, `pcapfilter` | [config.go](../internal/probe/gnutls/config.go) |
| NSPR/NSS | `nss_path`, `nspr_path` | [config.go](../internal/probe/nspr/config.go) |
| Bash | `bashpath`, `readline`, `errno` | [config.go](../internal/probe/bash/config.go) |
| MySQL | `MysqlPath`, `FuncName`, `Offset` | [config.go](../internal/probe/mysql/config.go) |
| PostgreSQL | `PostgresPath`, `FuncName`, `Offset` | [config.go](../internal/probe/postgres/config.go) |

MySQL/PostgreSQL module fields currently use Go's exported field names because
they have no explicit JSON tags. TLS modes accept `text`, `keylog`, and
`pcap`/`pcapng`; `text_source` selects `hook` or `pcapng` in text mode.
For OpenSSL/BoringSSL, omitted or empty `text_source` defaults to `pcapng`;
omitted or empty `ifname` selects a usable default-route Ethernet interface,
then falls back to interface traffic counters or an up interface. The startup
warning names the choice; set `ifname` explicitly to override it. Select `hook`
for function-hook capture without a capture interface.
GoTLS and GnuTLS still default to `hook`.
Packet capture and the pcapng text source require an interface. See
[event output semantics](event-forward-api.md) for mode/destination behavior.

## Examples

Replace example paths and filters with values valid on the capture host.
The following updates a running TLS probe and inherits its current event
address and rotation settings:

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/tls \
  -H 'Content-Type: application/json' \
  --data '{"opensslpath":"/usr/lib/x86_64-linux-gnu/libssl.so.3","capturemode":"text","text_source":"hook","pid":1234}'
```

To replace its destination with a TCP receiver that is already listening:

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/tls \
  -H 'Content-Type: application/json' \
  --data '{"opensslpath":"/usr/lib/x86_64-linux-gnu/libssl.so.3","capturemode":"text","pid":1234,"event_collector_addr":"tcp://127.0.0.1:9000","event_rotate_size_mb":0,"event_rotate_seconds":0}'
```

For a process originally started with `gotls`, use its field names and resend
the ELF path:

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/gotls \
  -H 'Content-Type: application/json' \
  --data '{"elf_path":"/absolute/path/to/go-app","capture_mode":"text","text_source":"hook","pid":1234}'
```

## Responses and failure behavior

```json
{"code":0,"module_type":"openssl","msg":"RespOK","data":null}
```

| HTTP status | `code` | Meaning |
| --- | --- | --- |
| 200 | 0 (`RespOK`) | The candidate generation started successfully |
| 400 | 4 (`RespConfigDecodeFailed`) | Empty/malformed JSON, type mismatch, or unavailable platform factory |
| 400 | 5 (`RespConfigCheckFailed`) | Runtime validation or generation-switch failure; inspect `msg` |
| 503 | 6 (`RespSendToChanFailed`) | Update queue cannot accept this request; retry with backoff |

Unknown paths and wrong HTTP methods use the HTTP router's 404/405 responses,
which need not have this JSON body. Unexpected handler failures can return 500.
`module_type` identifies the decoded config (`openssl`, `gotls`, `gnutls`,
`nspr`, `bash`, `mysql`, or `postgres`), not a successful cross-probe switch.

A validation failure leaves the active generation running. Once validation
passes, the old generation is stopped before the new one starts, so there can
be a capture gap. If the new start fails, the runtime attempts to restart the
previous configuration. Rollback or shutdown failures can terminate capture;
an HTTP 400 is not a guarantee that the old probe is still healthy.

Success is acknowledged after startup, not merely after queueing. A client
timeout or disconnect does not prove that a queued update was cancelled.
Keep the intended full configuration and last known-good configuration, inspect
operational logs on ambiguous results, and avoid rapid concurrent updates.
