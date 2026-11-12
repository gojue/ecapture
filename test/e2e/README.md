# eCapture E2E tests

The default E2E matrix focuses on TLS; non-TLS and CLI checks have separate
entry points:

- Linux on Ubuntu 22.04+ or Debian 13+: `tls` (OpenSSL), `gotls`, and `gnutls`.
  Supported architectures are x86_64 (kernel >= 4.18), aarch64/arm64 (>= 5.5),
  and loongarch64/loong64 (>= 6.6). GitHub-hosted CI uses Ubuntu; trusted
  LoongArch jobs use the dedicated Debian runner.
- Android 13/API 33 or newer: `tls` against the platform Conscrypt/BoringSSL library. CI covers every stable release from Android 13 through Android 16 (API 33-36).
- Every Linux TLS module is exercised in `text`, `keylog`, and `pcapng` modes; text covers hook and pcapng sources.
  Android continues to exercise `text`, `keylog`, and `pcapng`.
- The Linux `decrypt` cases assert plaintext arrives before probe shutdown,
  verify TLS 1.2 and 1.3, and independently decrypt the optional pcapng with
  tshark using its embedded DSB. They also check current HTTP event timestamps.
  OpenSSL also
  checks the sensitive reconstructed event on eCaptureQ.
- OpenSSL verifies live HTTP across bidirectional TLS 1.3 KeyUpdate with
  AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, plus DTLS 1.2 ECDHE-RSA
  AES-128/256-GCM with exact binary records, direction, epoch and sequence.
  These peers do not write keylogs; the pcapng DSB comes from eCapture.
  They also reset each completed DTLS connection with `SSL_clear()`, retaining
  its session while clearing client random. Subsequent hooks must not emit
  an uninitialized secret event; decoder errors remain fatal.
- Every Linux TLS module exercises text, keylog, and pcapng over stdout, file,
  local TCP, and binary WebSocket ByteSinks. Each representation is also
  observed by a strict typed eCaptureQ receiver.
- Every Linux TLS text suite performs same-probe HTTP reloads that inherit the
  original destination, switch to an explicit new destination only after
  success, and reject an invalid destination while the active output continues.
- The GoTLS pcapng text source additionally verifies that an HTTP body split
  across multiple TCP segments (PSH packets) is reconstructed completely and
  in order for both HTTP/1.1 and HTTP/2 keep-alive connections.
- GoTLS also tests server-first binary TLS 1.3 with `--text-raw` over file,
  stdout, TCP, WebSocket and eCaptureQ. ByteSinks are checked for exact bytes,
  per-direction offsets, live delivery and input-end markers; eCaptureQ checks
  the sensitive event and its metadata. Default message mode must report an
  unsupported protocol without emitting a false HTTP message.
- The GoTLS HTTP/3 baseline tests QUIC v1 and v2 separately on loopback with
  `QUIC_GO_DISABLE_GSO=true`, two concurrent connections and two request
  streams per connection. A server barrier waits for both connections' first
  requests before replying; each connection retains streams 0 and 4. It checks
  all eight request/response bodies and their connection/stream identities
  before probe shutdown, then independently decrypts every stream with tshark
  using eCapture's embedded DSB. Both endpoints are pinned to the selected
  version, and each captured connection's long headers must carry that version.
  The comparison associates connections by body labels, independent of handshake
  order. Each version has separate artifacts; the fixture never writes keylogs.
  0-RTT, migration, dynamic QPACK and GSO/GRO are outside this baseline.
  Its pinned quic-go dependency is isolated in `fixtures/http3/go.mod`; the
  first GoTLS text-suite build needs access to those Go module dependencies.
  Independent QUIC decryption requires tshark >= 4.4: older versions can
  misidentify loopback connections, lack QUIC v2, or omit responses from
  stream-follow output. Ubuntu 22.04/24.04 CI installs tshark from the
  [Wireshark stable PPA](https://launchpad.net/~wireshark-dev/+archive/ubuntu/stable).
- GoTLS additionally verifies DoT, DoH over HTTP/1.1/2/3, DoQ v1/v2, MQTT
  3.1.1, Redis RESP3 pipelines/push, SMTP STARTTLS and plain/HTTPS CONNECT with deterministic
  loopback peers. Exact directional bytes and protocol metadata must arrive
  before capture shutdown; all keys come from the GoTLS probe.
  QUIC v1/v2 DATAGRAM tests retain empty and repeated binary messages without
  inventing stream offsets. WSS covers negotiated permessage-deflate, text/binary
  fragmentation and interleaved ping/pong/close. SSE over HTTP/1.1/2/3, optional gzip expansion,
  and HTTP/2 gRPC empty/gzip messages must arrive while the response remains
  open; the harness then releases the peer and verifies trailers/completion.
  These are live integration checks, not the SDK's full cipher, ECH, dynamic
  QPACK, migration, Retry, 0-RTT, or key-update state matrix.
  DoQ/DATAGRAM peers use eight-byte client CIDs, verified on the wire.
  v1.4.0 still misroutes some zero-client-CID loopback captures with
  `ambiguous_connection_id`; this baseline does not establish zero-CID support.
- A separate strict common-config suite verifies file `--eventaddr` and
  operational-log isolation for Bash, Zsh, and the MySQL probe using local
  deterministic fixtures.

The tests require root and a real Linux/Android kernel with eBPF support. Building or running them on macOS is unsupported.
Linux and Android host-side pcapng validation requires Wireshark's `tshark`
and `editcap` >= 4.4. Ubuntu 22.04/24.04 hosts need the stable PPA linked above;
both CI workflows configure it before installing `tshark`.

## Test matrix

| Platform | Module/workload | text assertion | keylog assertion | pcapng assertion |
| --- | --- | --- | --- | --- |
| Ubuntu 22.04+ / Debian 13+ | OpenSSL C client | unique plaintext token with enriched connection tuple and no standalone connection records | valid TLS 1.2 and 1.3 NSS secrets | SHB, IDB, packets, TLS DSB |
| Linux advanced | 256 OpenSSL connections (64 concurrent) | n/a | n/a | at least 1024 packets, TLS DSB, no write/loss errors or per-packet INFO logs |
| Ubuntu 22.04+ / Debian 13+ | Go HTTPS client | unique plaintext token | valid TLS 1.2 and 1.3 NSS secrets | SHB, IDB, packets, TLS DSB |
| Ubuntu 22.04+ / Debian 13+ | GnuTLS C client | unique plaintext token | valid TLS 1.2 and 1.3 NSS secrets | SHB, IDB, packets, TLS DSB |
| Android 13+ | `app_process` + Conscrypt | unique plaintext token | valid TLS 1.2 and 1.3 NSS secrets | SHB, IDB, packets, TLS DSB |

The maintained Linux destination matrix is complete for every TLS module:

| Representation | stdout | file | TCP | binary WebSocket | eCaptureQ receiver |
| --- | --- | --- | --- | --- | --- |
| operational log | lifecycle records and event isolation | lifecycle records and event isolation | reconstructed lifecycle stream | reconstructed lifecycle stream | non-empty `PROCESS_LOG` |
| text | plaintext and log isolation | plaintext and log isolation | reconstructed plaintext stream | reconstructed plaintext stream | `PROCESS_LOG` plus normal `EVENT` |
| keylog | valid NSS secrets and decryption | valid NSS secrets and decryption | valid NSS secrets and decryption | valid NSS secrets and decryption | `PROCESS_LOG` plus sensitive keylog `EVENT` |
| pcapng | valid blocks, DSB, and decryption | valid blocks, DSB, and decryption | valid reconstructed artifact | valid reconstructed artifact | `PROCESS_LOG` plus sensitive packet `EVENT` |

All TLS traffic goes to a short-lived local server. Linux uses loopback directly. Android reaches the same host-side server through `adb reverse`, so the TLS suite does not depend on public DNS, public CAs, or a third-party response body.

The pcapng check parses the block structure instead of accepting any non-empty file. It requires:

- a Section Header Block;
- an Interface Description Block;
- at least one Enhanced Packet Block;
- at least one TLS Decryption Secrets Block.

Logs also fail on fatal errors, event-decode/preprocess/dispatch errors, lost perf samples, and eBPF load/attach/start errors. The OpenSSL text case checks both capture and operational logs. A probe merely staying alive is not considered a pass.

The output cases additionally exercise `--logaddr` over stdout, file, TCP, and
binary WebSocket. They require CLI and BaseProbe lifecycle records, prohibit
the deterministic plaintext and TLS secret labels there, and prohibit
lifecycle text in raw event artifacts. Network receivers compare the actual
byte stream. Pcapng network/stdout artifacts pass the same block and DSB
decryption checks as files. The strict eCaptureQ receiver requires both a
non-empty `PROCESS_LOG` and a correctly classified `EVENT`, including format,
sensitivity, timestamp, sequence, payload length, and original length;
connectivity alone cannot pass. The OpenSSL text/pcapng case also requires
the expected request PID and its deterministic argument token to survive the
Decryptor and eCaptureQ pipeline; the token must not appear in operational logs.
The request launcher records its kernel TGID before `exec`, using a temporary
raw syscall tracepoint restricted to a random thread name. This keeps the PID
comparison exact inside containers whose local PID differs from the captured
kernel TGID. The observer is closed before the client executes and needs no
tracefs mount. Failed assertions print only diagnostic fields, never argv or
captured payloads, before dedicated-runner cleanup removes private artifacts.

## Layout

```text
test/e2e/
├── fixtures/                 # deterministic TLS server and native clients
├── lib/testlib.sh            # shared assertions/result reporting
├── linux/                    # maintained Linux harness and module suites
├── android/                  # Android 13+ BoringSSL harness and workload
├── run_e2e.sh                # Linux suite runner
├── postgres_e2e_test.sh      # existing local database, read-only SELECT
├── edge_cases_test.sh        # CLI rejection and graceful shutdown
├── tls_e2e_test.sh           # compatibility entry points
├── gotls_e2e_test.sh
└── gnutls_e2e_test.sh
```

Bash, Zsh, and MySQL checks share `linux/common_config_test.sh`. Typed
eCaptureQ assertions live in each maintained TLS module suite;
`make e2e-ecaptureq` is an alias for that Linux matrix.

## Extending the suite

Use the maintained platform helpers and `lib/testlib.sh` assertions. New or
changed entry points must reject unsupported OS, architecture, and kernel
combinations before eBPF work. Keep traffic local and deterministic, use
unique captured tokens, bound waits, and install cleanup traps for only the
processes and network state the test owns. Preserve failure artifacts for
diagnosis; review and redact captures before sharing them.

For output changes, preserve CLI conflict checks and graceful-exit delivery
as well as the content, decryption, channel-isolation, and typed-message
assertions above. Add the case to the appropriate module runner and update
this matrix; do not create a second completion-status document.

## Linux

Install the test dependencies on Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install --yes \
  build-essential pkg-config libssl-dev libgnutls28-dev tshark python3
```

Build eCapture on Linux, then run all three modules:

```bash
make all
sudo make e2e-linux
```

For a LoongArch test host, use a Loong64 artifact from the supported Ubuntu
24.04 x86_64 cross-build or Debian native LLVM 22.1.8 build and
verify that it matches the intended source commit. A host running an existing
artifact does not need the build toolchain or kernel headers
to run a CO-RE artifact against its kernel BTF:

```bash
sudo env PATH="$PATH" ECAPTURE_BINARY=/absolute/path/to/ecapture \
  E2E_KEEP_ARTIFACTS=1 bash test/e2e/run_e2e.sh
```

`bash test/e2e/linux/platform_test.sh` checks distribution, root, architecture,
and kernel boundaries on Linux without loading eBPF. Platform acceptance alone
is not a capture pass. All existing plaintext, keylog, pcapng, reload, and
output assertions remain mandatory. The text suite also needs tshark because
it validates the pcapng text source.

Run one module or one mode:

```bash
sudo make e2e-tls
sudo make e2e-gotls
sudo make e2e-gnutls

sudo E2E_MODULES='tls gotls' E2E_MODES=text bash test/e2e/run_e2e.sh
sudo E2E_MODULES=gotls E2E_MODES='keylog pcapng' bash test/e2e/run_e2e.sh
sudo E2E_MODES=text bash test/e2e/run_e2e.sh  # includes hook and pcapng text sources
```

`make e2e` and `make e2e-basic` run the maintained Linux TLS matrix.
`make e2e-advanced` adds the OpenSSL pcapng burst regression case; it does not
select the separate non-TLS advanced cases.

### Non-TLS and CLI checks

Run the common-config suite separately. Bash/Zsh cases require the selected
shell and `script` for an interactive terminal; MySQL requires a C++ compiler.
All cases verify captured tokens, file `--eventaddr`, operational-log
isolation, and successful probe shutdown:

```bash
sudo env PATH="$PATH" bash test/e2e/linux/common_config_test.sh
sudo make e2e-bash
sudo make e2e-zsh
sudo make e2e-mysql
sudo make e2e-bash-advanced
sudo make e2e-mysql-advanced
```

`E2E_NON_TLS_MODULES` selects `bash`, `zsh`, and/or `mysqld` (all three by
default). `E2E_NON_TLS_ADVANCED=1` adds Bash command shapes and truncation, or
MySQL query shapes, truncation, and concurrent inputs. It defaults to `0`.
The MySQL cases call a local `dispatch_command` fixture: they validate probe
capture, not execution against a database server.

The separate opt-in `E2E_BASH_ERRNO=1` strictly reproduces a known production
bug: the Bash probe discards the matching return-value event. This case must
fail until the implementation is fixed; it is not passing default coverage:

```bash
sudo E2E_NON_TLS_MODULES=bash E2E_BASH_ERRNO=1 \
  bash test/e2e/linux/common_config_test.sh
```

`sudo make e2e-postgres` requires an existing local PostgreSQL server, `psql`,
a non-interactive connection as the selected OS user, and kernel 5.2+ so the
probe can filter by backend PID. This case-specific minimum does not change
the project's x86_64 runtime minimum of 4.18. It runs only
`SELECT pg_backend_pid()` and a literal-token `SELECT`, attaches to that
session's actual backend PID, and verifies captured SQL and output isolation.
The running server binary must retain an ELF symbol named `exec_simple_query`
(typically an unstripped PostgreSQL build). Stripped binaries without that
symbol are unsupported by the current probe, and the suite fails explicitly.
It does not provision or modify databases or tables. `PGHOST` must be unset
or one absolute Unix-socket directory; nonempty `PGHOSTADDR` or `PGSERVICE`,
TCP hosts, connection strings, and multiple hosts are rejected.

`sudo make e2e-edge-cases` verifies prompt rejection of invalid CLI inputs and
clean SIGINT/SIGTERM shutdown. It requires the OpenSSL development libraries
and a C compiler. These separate suites share the common-config lifecycle
helpers and the same Linux/root platform boundary.

## Android

The Android suite needs a rooted/userdebug Android 13+ device or emulator, `adb`, an Android build-tools installation containing `d8`, and an Android eCapture binary.
The host user must also be allowed to capture packets with `dumpcap`; CI grants
only the `cap_net_raw` and `cap_net_admin` capabilities to that binary.

Build the artifacts on Linux:

```bash
ANDROID=1 TARGET_ARCH=arm64 make nocore
ANDROID_API_LEVEL=33 bash test/e2e/android/build_boringssl_client.sh
```

Run the suite:

```bash
make setup-android-env
make e2e-android-all
```

The Java workload is intentional: Android `HttpsURLConnection` uses Conscrypt/BoringSSL. A statically built Go HTTPS client uses Go's own TLS implementation and therefore cannot validate the Android BoringSSL `tls` probe.

## CI coverage

Hosted Linux CI runs the TLS matrix on Ubuntu 22.04 and 24.04. Android CI
covers API 33–36. The workflow definitions are the source of truth for job
selection; these matrices are verification requirements, not a record that
an arbitrary local checkout has passed.

### LoongArch CI

The `loong64-e2e` job shares `E2E Tests` push/PR/manual triggers for trusted
repository refs; fork PRs retain the hosted Ubuntu jobs. It builds native
CO-RE at the event SHA and runs OpenSSL/GoTLS with stress. Debian GnuTLS and
non-CO-RE capture remain separate. See
[runner deployment, trusted refs and cleanup](../../docs/loong64-support.md#dedicated-runner).
The foreground Shell step runs this harness directly and streams case progress,
plaintext previews and PASS/FAIL results into Actions, like hosted jobs. Its
test log is also uploaded, including on failure; no E2E systemd unit is used.

## Configuration and artifacts

| Variable | Default | Purpose |
| --- | --- | --- |
| `E2E_MODULES` | `tls gotls gnutls` | Linux modules to run |
| `E2E_MODES` | `text keylog pcapng` | Output modes to run; text covers hook and pcapng sources |
| `E2E_STRESS` | `0` | Run burst regressions when set to `1` |
| `E2E_NON_TLS_MODULES` | `bash zsh mysqld` | Modules selected by the separate common-config suite |
| `E2E_NON_TLS_ADVANCED` | `0` | Add Bash/MySQL command, length, and concurrency cases where applicable |
| `E2E_BASH_ERRNO` | `0` | Opt into the strict known-failing Bash return-value regression |
| `E2E_POSTGRES_OS_USER` | `postgres` | OS user for the existing local PostgreSQL connection |
| `E2E_POSTGRES_DATABASE` | `postgres` | Existing database name; connection strings are rejected |
| `E2E_ARTIFACT_ROOT` | `/tmp/ecapture-e2e*` | Host artifact parent directory |
| `E2E_KEEP_ARTIFACTS` | `0` | Preserve successful test artifacts when set to `1` |
| `ECAPTURE_BINARY` | `bin/ecapture` | Override the eCapture binary |
| `ADB_SERIAL` | unset | Select a device when more than one is attached |
| `ANDROID_BORINGSSL_CLIENT` | generated jar in `android/` | Override the Android workload jar |

The harness preserves failed-suite artifacts. Hosted CI uploads captures with
`E2E_KEEP_ARTIFACTS=1`. On the dedicated LoongArch runner, raw evidence stays
private inside the job state and is deleted by the wrapper and runner cleanup
on success, failure or cancellation. Only the harness test log is uploaded,
with seven-day retention. Use a manual run outside the runner job state when
failure diagnosis requires retained keylogs or packet captures.

Every successful mode prints a `[PLAINTEXT]` line containing at most 50
characters of plaintext from the verified capture. Text mode reads the
eCapture event log; keylog mode decrypts a simultaneous packet capture with
the keys emitted by eCapture; pcapng mode preloads only eCapture's embedded TLS
Decryption Secrets Blocks with editcap before invoking tshark, so DSBs that
arrive after their packets also work. Pcapng previews include the 64-hex-character
`CLIENT_RANDOM` extracted from the captured ClientHello. The preview is
therefore capture evidence, not a copy of the workload's client output.

## GnuTLS implementation status

The GnuTLS probe attaches version-specific data and master-secret uprobes plus
TC programs for pcapng mode. Its strict text, keylog, and pcapng cases are CI
gates, matching the observable contracts used for OpenSSL and GoTLS. Keep the
version-to-asset mapping synchronized with the offsets in
`kern/gnutls_*_kern.c`; upstream 3.8.9 reuses the 3.8.7 asset, 3.8.10 has a
new layout, and 3.8.11-3.8.13 share the 3.8.11 asset. Distribution patches may
change private layouts without changing the library version; do not weaken
assertions to accept startup logs or empty artifacts.

Set `E2E_REQUIRE_TLS_METADATA=true` with the OpenSSL text suite to require JA3,
JA4, TLS version and cipher suite on the pcapng-source typed EVENT. These
handshake snapshots are provided by the pinned Decryptor v1.4.3 dependency.
