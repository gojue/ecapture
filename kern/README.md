# eBPF sources and TLS ABI references

This directory contains eBPF programs, shared headers, and version-specific
TLS library offsets. Use the [probe development guide](../docs/agent/probe-development.md)
for attachment/event contracts and the [offset tools guide](../utils/README.md)
for regenerating library layouts. Build targets are listed in
[`variables.mk`](../variables.mk).

## Directory responsibilities

- `*_kern.c`: compile-time entry points and library-version offset constants.
- `openssl*.h`, `boringssl*.h`, `gnutls*.h`: library-specific TLS hooks,
  data capture, and secret extraction.
- `gotls_kern.c`, `go_argument.h`: Go TLS hooks and argument access.
- Other module headers and entry points: shell, database, and NSPR probes.
- `bpf/`: BPF helper and architecture headers. LoongArch `vmlinux.h` is
  generated; see the [Loong64 guide](../docs/loong64-support.md).

## ABI source references

The following references explain historical OpenSSL `ssl_st`/`bio_st` layout
differences. They are research references, not layouts to copy into a new
version mapping:

- [OpenSSL `ssl_st` at a recorded source commit](https://github.com/openssl/openssl/blob/3e8f70c30d84861fcd257a6e280dc49e104eb145/ssl/ssl_local.h#L1068)
- [OpenSSL 1.1.1 `bio_st`](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h)
- [OpenSSL 1.0.0 `ssl_st`](https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/ssl/ssl.h#L1093)
- [OpenSSL 1.0.0 `bio_st`](https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/crypto/bio/bio.h)

Use the exact target library source, configuration, and architecture to measure
offsets. A shared field name does not imply a shared offset. Keep generated
constants, the Go library-to-asset mapping, and both asset variants consistent.

## TLS keylog labels

These labels describe the output secrets; their availability depends on the
library, negotiated TLS version, and captured events.

| Keylog label | Meaning |
| --- | --- |
| `CLIENT_RANDOM` | TLS 1.2 and earlier: client random plus session master secret |
| `CLIENT_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3 client handshake traffic secret |
| `SERVER_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3 server handshake traffic secret |
| `CLIENT_TRAFFIC_SECRET_0` | TLS 1.3 initial client application traffic secret |
| `SERVER_TRAFFIC_SECRET_0` | TLS 1.3 initial server application traffic secret |
| `CLIENT_EARLY_TRAFFIC_SECRET` | TLS 1.3 client early-data traffic secret |
| `EXPORTER_SECRET` | TLS 1.3 exporter master secret |
| `EARLY_EXPORTER_SECRET` | TLS 1.3 early exporter secret, when provided by the library |

For OpenSSL, `session->master_key` supplies the older TLS master secret.
The TLS 1.3 fields include application traffic secrets and exporter material;
handshake traffic secrets may require derivation from the captured handshake
secret and transcript hash in the
[Go keylog handler](../internal/probe/base/handlers/keylog_handler.go).

BoringSSL layouts vary across Android versions. The
[offset tool](../utils/boringssl-offset.c) emits feature macros and, where
available, the `SSL3_STATE` read/write secret offsets and endpoint role bit.
Read/write secrets must be mapped to the absolute client/server labels using
that role. Preserve this distinction when changing
[`boringssl_masterkey.h`](boringssl_masterkey.h).
