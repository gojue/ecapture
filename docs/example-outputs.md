# eCapture Example Outputs

These examples explain the current output formats. All displayed payloads,
process IDs, timestamps, and secret placeholders are synthetic; they are not
captured traffic or evidence of a successful run. For setup, see the
[README](../README.md).

Operational logs go to stderr and optionally `--logaddr`. Captured events go
to `--eventaddr`; for TLS, GoTLS, and GnuTLS the mode selects their format.
eCaptureQ can publish typed events alongside these byte outputs.

## TLS Module — Text Mode

```bash
sudo ecapture tls -m text --text-source hook --eventaddr stdout
```

Generate a request using an OpenSSL-linked application. A synthetic HTTP/1.1
write event looks like this (the payload uses CRLF line endings):

```text
[2026-01-01 12:00:00.000] PID:1234 TID:1234 Comm:curl FD:5 WRITE (37 bytes):
GET / HTTP/1.1
Host: example.com

```

The header identifies the process, thread, descriptor, direction, and captured
byte count. Available connection metadata adds a `Tuple:` field. Hook text
shows captured reads/writes, which may be fragments of application messages.

For complete HTTP/1.1 or HTTP/2 messages reconstructed from network packets
and TLS secrets, use the default pcapng text source (shown explicitly below):

```bash
sudo ecapture tls -m text --text-source=pcapng -i eth0 \
  --eventaddr http.events --pcapfile capture.pcapng 'tcp port 443'
```

Replace `eth0` and the filter with the target interface and traffic. This
source emits message metadata (direction, timestamp, network tuple, host,
connection identity, and HTTP/2 stream ID when present), followed by the
request or response. `--pcapfile` is optional here and saves the same pcapng
stream used for decryption. The plaintext source supports TCP TLS carrying
HTTP/1.1 or HTTP/2, not QUIC/HTTP/3.

## TLS Module — PcapNG Mode

```bash
sudo ecapture tls -m pcapng -i eth0 --eventaddr capture.pcapng 'tcp port 443'
```

The output is a binary pcapng file containing captured network packets and
embedded TLS Decryption Secrets Blocks (DSBs). After generating traffic and
stopping eCapture, open it in Wireshark or verify a known stream with tshark:

```bash
tshark -n -r capture.pcapng -o tls.keylog_file: -q -z follow,tls,ascii,0
```

The empty external keylog setting makes this check use the embedded DSB.
Confirm that the chosen stream contains the expected request and response;
a non-empty file alone does not prove successful capture or decryption.

## TLS Module — Keylog Mode

```bash
sudo ecapture tls -m keylog --eventaddr tls.keys
```

The file contains NSS Key Log lines. The following shows their shape only;
the angle-bracket placeholders are not valid hex values or usable secrets:

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

`--keylogfile tls.keys` remains a compatible primary-file alias in keylog
mode; do not set it together with `--eventaddr`.

## GoTLS and GnuTLS Modules

The same text, keylog, and pcapng output choices apply to GoTLS and GnuTLS.
Select the actual Go executable or GnuTLS library used by the workload:

```bash
sudo ecapture gotls --elfpath /path/to/go-client -m text
sudo ecapture gnutls --gnutls /path/to/libgnutls.so -m text
```

Run the matching application while capture is active. For keylog/pcapng,
select the mode and destination as above. Text defaults to the `pcapng` source;
packet capture selects an interface automatically. Use `-i <interface>` to
override it, or `--text-source hook` for function-hook plaintext capture.
GnuTLS support depends on the library's patch-specific asset mapping.

## Other Modules

```bash
sudo ecapture bash
sudo ecapture mysqld
```

Bash captures command events; MySQL captures queries at supported server
hooks. These are not terminal-output recording or database audit-log
replacements. See each command's `--help` for target and filtering options.
