# eCapture Example Outputs

These examples explain the current output formats. All displayed payloads,
process IDs, timestamps, and secret placeholders are synthetic; they are not
captured traffic or evidence of a successful run. For setup, see the
[README](../README.md).

Repeat `--output` to send runtime logs and captured events to multiple
destinations. Without an explicit value, it defaults to `stdout`. Terminal
outputs label every physical line as a log or event. Files and outgoing TCP
use Protobuf v2 JSON Lines, with `log_type` distinguishing the two record kinds.
Native keylog and pcapng artifacts use separate file parameters; `--output`
files receive only runtime logs in those two modes. See the
[output matrix](event-forward-api.md#destination-and-mode-matrix).

## TLS Module — Text Mode

```bash
sudo ecapture tls --model text --text-source pcapng --output stdout
```

Generate a request using an OpenSSL-linked application. The SDK reconstructs
messages from captured packets and TLS secrets. A synthetic excerpt of a
terminal event is shown below; preceding metadata identifies its timestamp,
protocol, direction, network endpoints, host and connection:

```text
[log_type=event capture_format=text module=tls] GET / HTTP/1.1\x0d
[log_type=event capture_format=text module=tls] Host: example.com\x0d
[log_type=event capture_format=text module=tls] \x0d
```

The terminal escapes control characters such as carriage returns. Operational
lines instead start with `[log_type=log module=tls]`. To retain a machine-readable
record alongside the terminal and optionally save the packets used for
reconstruction:

```bash
sudo ecapture tls --model text --text-source pcapng -i eth0 \
  --output stdout --output records.jsonl --pcapfile capture.pcapng 'tcp port 443'
```

Replace `eth0` and the filter with the target interface and traffic. The JSON
file contains both `LOG_TYPE_PROCESS_LOG` and `LOG_TYPE_EVENT` records. TEXT
records store the same formatted decoded output in
`event_payload.text.payload` (base64 in ProtoJSON), alongside process, network,
TLS and application-stream metadata when available. Decode the payload once;
it is not the whole JSON record. `--pcapfile` is optional in text mode and saves
the same pcapng stream used for decryption.

HTTP/1.1 and HTTP/2 are the default parsers. Explicit raw, application-protocol,
HTTP-event and UDP options are described in the
[text decryption guide](../README.md#live-decryption-for-text-output).
The older function-hook source remains available through `--text-source hook`,
but its reads and writes may contain message fragments.

## TLS Module — PcapNG Mode

```bash
sudo ecapture tls --model pcapng -i eth0 --pcapfile capture.pcapng \
  --output stdout --output runtime.jsonl 'tcp port 443'
```

`capture.pcapng` is a binary pcapng file containing captured network packets and
embedded TLS Decryption Secrets Blocks (DSBs). `runtime.jsonl` contains runtime
logs only. The terminal shows logs and labelled encoded-byte summaries, not
raw packet bytes. After generating traffic and stopping eCapture, open the
pcapng in Wireshark. For a strict decryption check, follow the
[embedded-secret verification steps](../README.md#live-decryption-for-text-output)
in the README; a non-empty file alone does not prove successful capture or
decryption.

## TLS Module — Keylog Mode

```bash
sudo ecapture tls --model keylog --keylogfile tls.keys \
  --output stdout --output runtime.jsonl
```

`tls.keys` contains NSS Key Log lines; `runtime.jsonl` contains runtime logs
only. The terminal labels each NSS line as an event. The following shows the
native file shape only; angle-bracket placeholders are not valid hex values
or usable secrets:

```text
CLIENT_RANDOM <client-random-hex> <master-secret-hex>
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client-random-hex> <secret-hex>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client-random-hex> <secret-hex>
```

Keylog output contains no packets. Capture the target traffic separately,
then combine that capture with the generated keylog:

```bash
tshark -n -r traffic.pcapng -o tls.keylog_file:tls.keys -q -z follow,tls,ascii,0
```

Both native modes require an explicit local artifact path, distinct from any
`--output` file. To receive native events remotely, use `--output tcp://HOST:PORT`
or `--stream-listen ws://HOST:PORT/PATH`. Receivers decode the v2 envelope and
append the KEYLOG/PCAPNG `data` bytes in arrival order; see the
[receiver example](../examples/ecaptureq_client/README.md) for session and
partial-file handling. WebSocket clients must negotiate `ecapture.v2`.

## GoTLS and GnuTLS Modules

The same text, keylog, and pcapng output choices apply to GoTLS and GnuTLS.
Select the actual Go executable or GnuTLS library used by the workload:

```bash
sudo ecapture gotls --elfpath /path/to/go-client --model text --text-source pcapng
sudo ecapture gnutls --gnutls /path/to/libgnutls.so --model text --text-source pcapng
```

Run the matching application while capture is active. For keylog/pcapng,
select the mode and native file as above. Text defaults to the `pcapng` source;
packet capture selects an interface automatically. Use `-i <interface>` to
override it. GnuTLS support depends on the library's patch-specific asset mapping.

## Other Modules

```bash
sudo ecapture bash
sudo ecapture mysqld
```

Bash captures command events; MySQL captures queries at supported server
hooks. These are not terminal-output recording or database audit-log
replacements. See each command's `--help` for target and filtering options.
