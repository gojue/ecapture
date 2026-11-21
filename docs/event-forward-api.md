# Output and subscription API

[中文](event-forward-api-zh_Hans.md)

TLS (OpenSSL/BoringSSL), GoTLS and GnuTLS share three startup options:

| Option | Purpose | Default |
| --- | --- | --- |
| Repeatable `--output` | Write runtime logs and captured events to selected destinations | `stdout` |
| `--stream-listen ws://HOST:PORT/PATH` | Listen for clients pulling Protobuf v2 records | Disabled |
| `--config-listen HOST:PORT` | Listen for HTTP configuration updates | Disabled |

Explicit `--output` values replace the default. Repeat the flag to supply an
array; values are not a comma-separated list. `--listen`, `--eventaddr`,
`--logaddr`, `-l`, `--ecaptureq` and the former event rotation flags are removed,
without aliases. `console`, outgoing WS/WSS and `listen+ws://` are not supported
`--output` values. Update startup scripts and receiving decoders together.

## Destination and mode matrix

| Destination | Connection direction | text | keylog / pcapng |
| --- | --- | --- | --- |
| `stdout` / `stderr` | Terminal | Readable operational logs and text events | Pcapng shows only operational logs. Keylog also shows labelled NSS records. |
| Local path / `file:///PATH` | Write local file | JSON Lines: `PROCESS_LOG` and `EVENT` | JSON Lines: `PROCESS_LOG` only |
| `tcp://HOST:PORT` | Actively connect to receiver | JSON Lines: `PROCESS_LOG` and TEXT `EVENT` | JSON Lines: `PROCESS_LOG` and native KEYLOG/PCAPNG `EVENT` |
| `--stream-listen ws://…` | Clients connect to eCapture | Binary Protobuf v2 records | Binary Protobuf v2 with native KEYLOG/PCAPNG bytes |

Each terminal line has `log_type=log` or `log_type=event`, plus `module`; event
lines also have `capture_format`. JSON uses the same `LogEntry` schema as Protobuf,
with `log_type` separating records and `event_payload.capture_format` selecting event content.
There is no raw JSON-file-to-pcapng redirection: save native files explicitly.

| Capture mode (`--model`, `-m`) | Native file requirement |
| --- | --- |
| `text --text-source pcapng` | Optional `--pcapfile` and `--keylogfile`; event remains decoded TEXT |
| `keylog` | Explicit `--keylogfile PATH`, NSS Key Log format |
| `pcapng` | Explicit `--pcapfile PATH`, pcapng with TLS Decryption Secrets Blocks; `--keylogfile` is optional |

No default native filename is created. Native artifact arguments must be local
files, separate from JSON output files; stdout, stderr and network URLs are not
native artifact destinations. The selected capture interface is automatic when
omitted; set `-i` to override it. GoTLS also requires `--elfpath`.

```bash
# Terminal plus a combined JSON Lines file.
sudo ./bin/ecapture tls --model text --text-source pcapng \
  --output stdout --output /tmp/records.jsonl

# A JSON TCP receiver must already be listening.
sudo ./bin/ecapture gotls --model text --text-source pcapng \
  --elfpath /path/to/go-client --output tcp://127.0.0.1:9000

# Native capture and an operational JSON log file are different files.
sudo ./bin/ecapture tls --model pcapng -i eth0 --pcapfile /tmp/capture.pcapng \
  --output /tmp/runtime.jsonl --stream-listen ws://127.0.0.1:28257/

sudo ./bin/ecapture gnutls --model keylog --keylogfile /tmp/gnutls.keys \
  --output stderr --output tcp://127.0.0.1:9000
```

Choose library/binary paths, filters and privileges appropriate to the target
Linux/Android host. The listener offers WS, without built-in TLS or application
authentication; examples bind loopback. Its URL path is the subscription path.

## Receiving v2

WebSocket clients must negotiate `ecapture.v2`; each binary message is one
`LogEntry`. JSON receivers read complete newline-delimited records. Use the
[protocol reference](../protobuf/PROTOCOLS.md) and
[Go example](../examples/ecaptureq_client/README.md). V1 payloads are not supported.

Dispatch `PROCESS_LOG` to operational logging, `HEARTBEAT` to health handling,
and `EVENT` by its matching format/oneof. Preserve all TEXT metadata. After
ProtoJSON decoding, append KEYLOG `keylog.data` or PCAPNG `pcapng.data` bytes
in order to a native file. Bytes fields are base64 in JSON only. Messages can
split native lines/blocks; pcapng includes real encoder headers, packets and
secrets, not a sequence of packet summaries.

The listener retains up to 128 operational logs but no event history. A late
pcapng client starts a new independent session, with headers and future
packets/secrets only. Earlier TLS handshakes/keys are not replayed, so existing
connections may be undecryptable. Bounded queues disconnect slow consumers;
there is no durable delivery or resume protocol.

## Generation and completion rules

Startup output destinations are process-lifetime configuration and cannot be
changed through HTTP. A successful reload ends the old capture generation,
drains its encoders and connections, and starts another. TCP output closes and
reconnects to its configured receiver; WS clients reconnect themselves. Use a
new native filename per connection, even when the capture mode is unchanged.

For WS, only successful drain followed by Close 1000 can establish transport
completion; 1011, abrupt EOF, timeout and receiver interruption must leave
`.partial` artifacts. The example also flushes/closes and validates framing
before finalizing. TCP EOF has no success status: retain `.partial` until an
external completion signal establishes success. Neither framing nor normal
close proves lossless capture or successful TLS decryption.

See [HTTP configuration updates](remote-config-update-api.md),
[community integrations](event-forward.md), and
[output architecture](agent/output-pipeline.md).
