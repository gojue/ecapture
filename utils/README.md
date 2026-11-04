# TLS structure offset tools

These tools compile against a TLS library's internal headers and emit the
field offsets used by eCapture's eBPF probes. The version-specific files in
`kern/` are source inputs, not disposable build artifacts.

See the [probe development guide](../docs/agent/probe-development.md) for
library mappings, asset variants, and verification requirements.
[简体中文](README-zh_Hans.md)

## Tools

| Files | Purpose |
| --- | --- |
| `boringssl_android_offset.sh`, `boringssl-offset.c` | Android 13–17 BoringSSL offsets |
| `boringssl_non_android_offset.sh`, `boringssl-offset.c` | Upstream BoringSSL offsets |
| `gnutls_offset.sh`, `gnutls_offset.c` | Versioned GnuTLS offsets from configured source |
| `openssl_offset_*.sh`, `openssl_*_offset.c` | OpenSSL 1.0.2, 1.1.0, 1.1.1, 3.x, and 4.0 mappings |
| `protobuf_visualizer/` | Separate WebSocket/Protobuf [debugging client](protobuf_visualizer/README.md) |

## Running the tools

Compile and execute the offset tools on Linux, including when the target is
Android. The measured layout must match the target library's version, build
configuration, and CPU ABI; do not assume offsets generated on a different
architecture are interchangeable. See the [build guide](../docs/agent/build-test.md)
for supported environments.

Run these commands from the repository root:

```bash
bash utils/boringssl_android_offset.sh
bash utils/boringssl_non_android_offset.sh
bash utils/openssl_offset_3.5.sh
bash utils/gnutls_offset.sh 3.8.11
```

OpenSSL/BoringSSL scripts fetch library sources into `deps/`, check out the
mapped version, compile an offset tool, and write the corresponding file in
`kern/`. Existing output files are skipped. Use an isolated checkout when
regenerating tracked files for comparison; review changes before adopting them.

The scripts' version tables may map several library releases to one shared
asset. Preserve those mappings even when the shell workflows look similar.
Generating an offset file alone does not add runtime support: update the Go
selector and build target list when needed, then validate both asset variants
against the real library.

## BoringSSL field detection

`boringssl-offset.c` needs C++17. It uses `std::void_t` and partial template
specialization to select emitters only when the relevant field exists.
`offsetof(T, field)` remains a dependent expression, so a removed field is not
compiled in an unselected emitter. A non-template `if constexpr` is not a
substitute for this pattern.

The emitted macros are consumed by
[`boringssl_const.h`](../kern/boringssl_const.h) and
[`boringssl_masterkey.h`](../kern/boringssl_masterkey.h):

| Layout change | Tool/consumer contract |
| --- | --- |
| `ssl_st::version` absent in Android 16+ | Emit `SSL_SESSION_ST_SSL_VERSION`; use the alternate version/layout path |
| `ssl_session_st::secret_length` absent | Emit the `0xFF` sentinel for the maximum master-secret length |
| `SSL3_STATE::version` available | Emit `BSSL__SSL3_STATE_VERSION` for protocol selection |
| Public `SSL3_STATE` traffic-secret vectors | Emit read/write storage and length offsets; use the endpoint role to select client/server labels |
| `ssl_cipher_st::id` renamed in Android 17 | Emit `SSL_CIPHER_ST_ID` from `protocol_id` |

The TLS 1.3 handshake secret spacing is derived in `boringssl_const.h`: raw
arrays use 48-byte steps, while the relevant `InplaceVector` layout uses
49-byte steps. Do not hand-edit offsets to compensate for a new layout.
Add the necessary detector/emitter and update its consumers, then add the
version to the Android driver's map and validate it.

The Android driver can continue with cached branches when `git fetch --tags`
fails. Record the actual source revision used; this fallback does not prove
that the cached source matches a newer release.

## GnuTLS source identity and comparison

`gnutls_offset.sh` accepts one or more versions in `3.8.0` through `3.8.13`;
without arguments it iterates that range. This generation range is distinct
from the runtime's supported version-to-asset table. The default compiler is
`clang`, overridable with `CC`.

Use a separate output directory to compare regenerated offsets:

```bash
GNUTLS_OUTPUT_DIR=/tmp/ecapture-gnutls-offsets \
  bash utils/gnutls_offset.sh 3.8.11
```

By default the script clones and configures the selected upstream release.
For a distribution-patched library, supply its already configured source and
exact source identity; this form accepts exactly one version:

```bash
GNUTLS_SOURCE_DIR=/path/to/configured/gnutls \
GNUTLS_SOURCE_ID='<full-git-commit-or-release-archive-sha256>' \
GNUTLS_OUTPUT_DIR=/tmp/ecapture-gnutls-offsets \
  bash utils/gnutls_offset.sh 3.8.11
```

Replace the angle-bracket placeholder before running. The script checks
`config.h` against the requested version and records the source identity and
`config.h` SHA256 in the generated file. Configure/compile failures prevent
publishing the output. Keep the library's real build options and downstream
patches when preparing the source.
