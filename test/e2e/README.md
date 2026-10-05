# eCapture E2E tests

This directory keeps the actively maintained TLS E2E scope small and explicit:

- Linux on GitHub Actions Ubuntu 22.04 or newer: `tls` (OpenSSL), `gotls`, and `gnutls`.
- Android 13/API 33 or newer: `tls` against the platform Conscrypt/BoringSSL library. CI covers every stable release from Android 13 through Android 16 (API 33-36).
- Every module is exercised in `text`, `keylog`, and `pcapng` modes.

The tests require root and a real Linux/Android kernel with eBPF support. Building or running them on macOS is unsupported.

## Test matrix

| Platform | Module/workload | text assertion | keylog assertion | pcapng assertion |
| --- | --- | --- | --- | --- |
| Ubuntu 22.04+ | OpenSSL C client | unique plaintext token | valid TLS 1.2 and 1.3 NSS secrets | SHB, IDB, packets, TLS DSB |
| Ubuntu 22.04+ | Go HTTPS client | unique plaintext token | valid TLS 1.2 and 1.3 NSS secrets | SHB, IDB, packets, TLS DSB |
| Ubuntu 22.04+ | GnuTLS C client | unique plaintext token | valid TLS 1.2 and 1.3 NSS secrets | SHB, IDB, packets, TLS DSB |
| Android 13+ | `app_process` + Conscrypt | unique plaintext token | valid TLS 1.2 and 1.3 NSS secrets | SHB, IDB, packets, TLS DSB |

All traffic goes to a short-lived local TLS server. Linux uses loopback directly. Android reaches the same host-side server through `adb reverse`, so the suite does not depend on public DNS, public CAs, or a third-party response body.

The pcapng check parses the block structure instead of accepting any non-empty file. It requires:

- a Section Header Block;
- an Interface Description Block;
- at least one Enhanced Packet Block;
- at least one TLS Decryption Secrets Block.

Logs also fail on fatal errors, event-decode errors, lost perf samples, and eBPF load/attach/start errors. A probe merely staying alive is not considered a pass.

## Layout

```text
test/e2e/
├── fixtures/                 # deterministic TLS server and native clients
├── lib/testlib.sh            # shared assertions/result reporting
├── linux/                    # maintained Linux harness and module suites
├── android/                  # Android 13+ BoringSSL harness and workload
├── run_e2e.sh                # Linux suite runner
├── tls_e2e_test.sh           # compatibility entry points
├── gotls_e2e_test.sh
└── gnutls_e2e_test.sh
```

Older Bash/database/ecaptureQ scripts remain outside this maintained TLS scope and are not called by `make e2e`.

## Linux

Install the test dependencies on Ubuntu:

```bash
sudo apt-get update
sudo apt-get install --yes \
  build-essential pkg-config libssl-dev libgnutls28-dev tshark
```

Build eCapture on Linux, then run all three modules:

```bash
make all
sudo make e2e-linux
```

Run one module or one mode:

```bash
sudo make e2e-tls
sudo make e2e-gotls
sudo make e2e-gnutls

sudo E2E_MODULES='tls gotls' E2E_MODES=text bash test/e2e/run_e2e.sh
sudo E2E_MODULES=gotls E2E_MODES='keylog pcapng' bash test/e2e/run_e2e.sh
```

`make e2e`, `make e2e-basic`, and `make e2e-advanced` are compatibility aliases for the maintained Linux matrix.

## Android

The Android suite needs a rooted/userdebug Android 13+ device or emulator, `adb`, an Android build-tools installation containing `d8`, and an Android eCapture binary.
The host user must also be allowed to capture packets with `dumpcap`; CI grants
only the `cap_net_raw` and `cap_net_admin` capabilities to that binary.

Build the artifacts on Linux:

```bash
ANDROID=1 CROSS_ARCH=arm64 make nocore
ANDROID_API_LEVEL=33 bash test/e2e/android/build_boringssl_client.sh
```

Run the suite:

```bash
make setup-android-env
make e2e-android-all
```

The Java workload is intentional: Android `HttpsURLConnection` uses Conscrypt/BoringSSL. A statically built Go HTTPS client uses Go's own TLS implementation and therefore cannot validate the Android BoringSSL `tls` probe.

## Configuration and artifacts

| Variable | Default | Purpose |
| --- | --- | --- |
| `E2E_MODULES` | `tls gotls gnutls` | Linux modules to run |
| `E2E_MODES` | `text keylog pcapng` | Modes to run |
| `E2E_ARTIFACT_ROOT` | `/tmp/ecapture-e2e*` | Host artifact parent directory |
| `E2E_KEEP_ARTIFACTS` | `0` | Preserve successful test artifacts when set to `1` |
| `ECAPTURE_BINARY` | `bin/ecapture` | Override the eCapture binary |
| `ADB_SERIAL` | unset | Select a device when more than one is attached |
| `ANDROID_BORINGSSL_CLIENT` | generated jar in `android/` | Override the Android workload jar |

Failed-suite artifacts are always preserved. CI sets `E2E_KEEP_ARTIFACTS=1` and uploads them.

Every successful mode prints a `[PLAINTEXT]` line containing at most 50
characters from the verified capture. Text mode reads the eCapture event log;
keylog mode decrypts a simultaneous packet capture with the keys emitted by
eCapture; pcapng mode decrypts eCapture's own pcapng output. The preview is
therefore capture evidence, not a copy of the workload's client output.

## Current GnuTLS implementation status

The current `internal/probe/gnutls/gnutls_probe.go` is still a scaffold and does not attach the data, master-secret, or TC programs. The GnuTLS E2E suite is deliberately strict and exposes that implementation gap. CI executes the full contract as a visible non-gating step; direct `make e2e-linux` runs remain strict and fail. Do not weaken the assertions to pass on startup logs or empty artifacts; the contract should turn green when the probe implements the same three observable behaviors as OpenSSL and GoTLS.
