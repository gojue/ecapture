# Runtime configuration HTTP API

[中文](remote-config-update-api-zh_Hans.md)

Enable the configuration service explicitly with `--config-listen`; it is
disabled by default. It restarts the running probe with a validated replacement
configuration. The listener is separate from Protobuf `--stream-listen` and has
no built-in TLS or application authentication; this example binds loopback.

```bash
sudo ./bin/ecapture tls --model text --text-source pcapng \
  --config-listen 127.0.0.1:28256 --output stdout --output /tmp/records.jsonl
```

Use `POST` with `Content-Type: application/json`. `--listen` and the old output
CLI flags are removed; there is no compatibility alias.

## Core module endpoints

Send updates for the probe selected at process startup. The factory probe type
is retained; the API cannot switch between TLS, GoTLS and GnuTLS.

| POST path | Configuration | Availability |
| --- | --- | --- |
| `/tls`, `/openssl`, `/boringssl` | OpenSSL/BoringSSL | Linux and Android |
| `/gotls` | GoTLS | Linux and Android |
| `/gnutls` | GnuTLS | Linux; Android factory returns HTTP 400 |

## Replacement and output lifetime

The server decodes a **fresh module configuration**, validates it, then applies
it. This is not a general JSON patch. Omitted common/module fields take factory
defaults or zero values. Resend library/ELF paths, mode, filters and options you
need to retain. In core text mode, an omitted/empty `text_source` becomes
`pcapng`; an omitted `ifname` triggers automatic interface selection.

`--output`, `--stream-listen` and `--config-listen` are process-lifetime startup
settings. They survive reload through runtime dependencies and cannot be changed
by HTTP. Requests containing new output-route fields or removed legacy fields
are rejected, including explicit `null`; they are not ignored or inherited.
Examples include `output`, `outputs`, `stream_listen`, `config_listen`,
`eventaddr`, `event_collector_addr`, `logaddr`, `logger_addr`, `ecaptureq`,
`listen`, `event_rotate_size_mb` and `event_rotate_seconds`.

Native `pcapfile`/`keylogfile` module settings remain generation configuration.
A keylog replacement requires an explicit keylog file, and a pcapng replacement
requires an explicit pcap file. Use a new native filename for a new generation;
text-mode artifact files are optional. Native destinations must be local files,
separate from JSON output. Other unknown JSON fields may still be ignored, so
use documented keys rather than assuming arbitrary field names are validated.

On reload, old-generation TCP/WS output connections drain and close. TCP output
reconnects to its configured destination; WS clients reconnect themselves.
Each connection owns a separate native artifact. A late subscription starts
from fresh pcapng headers and future packets/secrets, without history replay.
See [output and completion rules](event-forward-api.md).

## Request fields

Common fields are defined by [BaseConfig](../internal/config/base_config.go)
and [CommonConfig](../internal/config/common.go):

| JSON field | Type | Meaning |
| --- | --- | --- |
| `pid`, `uid` | unsigned integer | Process/user filters; 0 disables the filter |
| `debug`, `is_hex` | boolean | Debug and text presentation options |
| `btf_mode` | unsigned integer | 0 auto, 1 CO-RE, 2 non-CO-RE; must match available assets |
| `per_cpu_map_size` | integer | Positive buffer bytes; CLI `--mapsize` uses pages |
| `cgroup_path` | string | cgroup filter where supported |
| `perf_reorder`, `perf_reorder_lag_ms` | boolean, unsigned integer | Supported reader reorder settings |

Leave `byte_code_file_mode` at its factory default unless matching the embedded
asset mode deliberately. `truncate_size` has no production consumer.

| Module | Fields | Definition |
| --- | --- | --- |
| TLS | `opensslpath`, `capturemode`, `text_source`, `keylogfile`, `pcapfile`, `ifname`, `pcapfilter` | [config.go](../internal/probe/openssl/config.go) |
| GoTLS | `elf_path`, `capture_mode`, `text_source`, `keylog_file`, `pcap_file`, `ifname`, `pcap_filter` | [config.go](../internal/probe/gotls/config.go) |
| GnuTLS | `gnutlspath`, `capturemode`, `text_source`, `keylogfile`, `pcapfile`, `ifname`, `pcapfilter` | [config.go](../internal/probe/gnutls/config.go) |

Capture modes are `text`, `keylog`, and `pcapng` (`key`/`pcap` spellings remain
mode values). Core integrations use `text_source: "pcapng"`. Interface selection
prefers a usable default-route Ethernet interface, then counters or an up
interface; startup logs identify it. Set `ifname` explicitly to override.
`text_source: "hook"` remains available during plaintext-hook deprecation.

## Examples

Keep existing output routes while replacing TLS capture options:

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/tls \
  -H 'Content-Type: application/json' \
  --data '{"opensslpath":"/usr/lib/x86_64-linux-gnu/libssl.so.3","capturemode":"text","text_source":"pcapng","ifname":"eth0","pid":1234}'
```

For a process started with `gotls`, use its field names and resend the ELF path:

```bash
curl --fail-with-body -X POST http://127.0.0.1:28256/gotls \
  -H 'Content-Type: application/json' \
  --data '{"elf_path":"/absolute/path/to/go-app","capture_mode":"pcapng","pcap_file":"/tmp/generation-2.pcapng","ifname":"eth0","pid":1234}'
```

Changing output destinations requires restarting the process with new CLI
arguments. Sending `{"output":["tcp://127.0.0.1:9000"]}` is rejected.

## Responses and failure behavior

```json
{"code":0,"module_type":"openssl","msg":"RespOK","data":null}
```

| HTTP status | code | Meaning |
| --- | --- | --- |
| 200 | 0 (`RespOK`) | Replacement generation started |
| 400 | 4 (`RespConfigDecodeFailed`) | Empty/malformed JSON, type mismatch, forbidden route fields, or unavailable factory |
| 400 | 5 (`RespConfigCheckFailed`) | Validation or generation switch failed; inspect `msg` |
| 503 | 6 (`RespSendToChanFailed`) | Update queue full; retry with backoff |

Router 404/405 and unexpected 500 responses may have different bodies.
`module_type` identifies the decoded configuration, not a cross-module switch.
Validation failure leaves the active generation running. Once validation passes,
the old generation stops before the new one starts, so there can be a capture
gap. A failed new start triggers an attempt to restore the previous configuration;
rollback/shutdown failure can terminate capture. HTTP 400 alone does not prove
that the old probe is healthy.

Success is acknowledged after startup, not merely queueing. Client timeout or
disconnect does not prove that a queued update was cancelled. Keep the intended
configuration and last known-good configuration, inspect operational logs on
ambiguous results, and avoid concurrent reload requests.
