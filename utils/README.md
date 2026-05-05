# utils — Struct Offset Generation Scripts

This directory contains tooling to generate eBPF-compatible C header files
(`kern/boringssl_a_XX_kern.c`, `kern/boringssl_na_kern.c`, `kern/gnutls_*.c`,
`kern/openssl_*.c`, …).  Each header defines `#define` constants for the byte
offsets of TLS-critical fields within the target library's internal structs,
which the eBPF probes in `kern/` use to read plaintext keys from process memory.

---

## Directory layout

```
utils/
├── boringssl-offset.c            # C++17 offset-probe tool (Android BoringSSL)
├── boringssl_android_offset.sh   # Driver: Android 13-16 BoringSSL
├── boringssl_non_android_offset.sh # Driver: non-Android (upstream) BoringSSL
├── gnutls_offset.c / gnutls_offset.sh
├── openssl_*_offset.c / openssl_offset_*.sh
└── README.md                     # this file
```

---

## Quick start

All scripts **must be run from the project root directory** (the one that
contains `go.mod`):

```bash
# Android BoringSSL (android13 – android16)
bash utils/boringssl_android_offset.sh

# Non-Android (upstream) BoringSSL
bash utils/boringssl_non_android_offset.sh

# GnuTLS
bash utils/gnutls_offset.sh

# OpenSSL (pick the right version script)
bash utils/openssl_offset_3.5.sh
```

Generated files are written to `kern/`.  If a target file already exists the
script skips that version.  Delete the file to force regeneration.

> **Platform requirement**: scripts compile native C++ and must run on a
> Linux / Android build host (x86\_64 kernel ≥ 4.18, aarch64 ≥ 5.5).
> They will not work on macOS.  Use the remote Linux server via SSH:
> ```bash
> ssh cfc4n@172.16.71.128
> cd /home/cfc4n/project/ecapture
> bash utils/boringssl_android_offset.sh
> ```

---

## How `boringssl_android_offset.sh` works

### Overview

```
boringssl_android_offset.sh
        │
        ├─ git clone / checkout  android13-release … android16-release
        │
        ├─ compile  boringssl-offset.c  (C++17, against boringssl headers)
        │
        ├─ run ./offset  →  emits #define constants + feature-flag macros
        │
        └─ wrap output  →  kern/boringssl_a_XX_kern.c
```

### Adding a new Android version

Edit the `sslVerMap` in `boringssl_android_offset.sh` and add one line:

```bash
sslVerMap["5"]="17"   # android17-release
```

Then re-run the script.  No other changes are needed in most cases—see the
[Design philosophy](#design-philosophy) section below.

---

## `boringssl-offset.c` — the offset-probe tool

### Purpose

The tool is compiled **against the target library's own headers**, so
`offsetof(struct_name, field)` returns the exact byte offset for that
specific library version and architecture.

It produces output like:

```c
// ssl_st->session
#define SSL_ST_SESSION 0x58

// ssl_session_st->ssl_version
#define SSL_SESSION_ST_SSL_VERSION 0x4
```

These `#define` values are pasted verbatim into the generated kern header and
consumed by `kern/boringssl_masterkey.h` at eBPF compile time.

### Design philosophy — automatic version detection via C++17 type traits

Older versions of the tool used a fixed field list and relied on `sed`
post-processing in the shell script to cope with fields that were removed or
renamed between Android releases.  This approach was fragile: every new
Android version that changed a struct required a new version-specific `sed`
rule.

The current tool uses **C++17 type traits (`std::void_t` + SFINAE)** to probe
whether a field is publicly accessible at compile time, then selects the
correct output via **partial template specialisation**:

```
                  field present?
                  ┌─── yes ──→  emit offsetof(T, field)
 type-trait probe ┤
                  └─── no  ──→  emit alternative macro / sentinel
```

Key design rules:

1. **`if constexpr` is NOT used** for this purpose.  In a non-template
   function, both branches of `if constexpr` are still parsed and checked by
   the compiler, so `offsetof(T, removed_field)` would be a hard error even
   in the untaken branch.

2. **Partial specialisation IS used**.  The body of
   `emit_foo<T, true>::emit()` contains `offsetof(T, field)` as a
   *dependent expression* (it depends on `T`).  The compiler only instantiates
   and checks it when `T` is actually substituted—i.e. only when the
   `Present=true` branch is selected.

3. **Feature-flag macros are a by-product of detection**.  When a field is
   absent, the tool emits an *alternative* macro whose presence in the
   generated header signals downstream consumers:

   | Absent field | Emitted macro | Consumed by |
   |---|---|---|
   | `ssl_st::version` | `SSL_SESSION_ST_SSL_VERSION` | `boringssl_const.h`, `boringssl_masterkey.h` |
   | `ssl_session_st::secret_length` | `SSL_SESSION_ST_SECRET_LENGTH 0xFF` (sentinel) | `boringssl_masterkey.h` |
   | *(none)* | `BSSL__SSL3_STATE_VERSION` (when present) | `boringssl_masterkey.h` |

### Currently tracked field changes

| Android version | Change | Tool behaviour |
|---|---|---|
| ≤ 15 | `ssl_st::version` present | emits `SSL_ST_VERSION` |
| 16+ | `ssl_st::version` **removed** | emits `SSL_SESSION_ST_SSL_VERSION` (feature flag) |
| ≤ 15 | `ssl_session_st::secret_length` present | emits `SSL_SESSION_ST_SECRET_LENGTH <offset>` |
| 16+ | `ssl_session_st::secret_length` **removed** | emits `SSL_SESSION_ST_SECRET_LENGTH 0xFF` (sentinel) |
| ≤ 15 | `SSL3_STATE::version` absent | nothing emitted |
| 16+ | `SSL3_STATE::version` **added** | emits `BSSL__SSL3_STATE_VERSION` (feature flag) |

### Supporting future Android versions

If a new Android release changes or removes a struct field:

1. **Add a new type-trait probe** in `boringssl-offset.c`:
   ```cpp
   template <typename T, typename = void>
   struct foo_has_new_field : std::false_type {};
   template <typename T>
   struct foo_has_new_field<T, std::void_t<decltype(std::declval<T>().new_field)>>
       : std::true_type {};
   ```

2. **Add a new emitter pair** (primary template + `<T,true>` partial spec):
   ```cpp
   template <typename T, bool Present>
   struct emit_new_field { static void emit() { /* absent: emit alternative */ } };
   template <typename T>
   struct emit_new_field<T, true> { static void emit() { format("foo", "new_field", offsetof(T, new_field)); } };
   ```

3. **Call the emitter** from `main()`:
   ```cpp
   emit_new_field<foo_t, foo_has_new_field<foo_t>::value>::emit();
   ```

4. **Handle the feature flag** in `boringssl_const.h` or
   `boringssl_masterkey.h` using `#ifdef NEW_FEATURE_FLAG`.

5. **Register the new Android version** in `boringssl_android_offset.sh`:
   ```bash
   sslVerMap["5"]="17"   # android17-release
   ```

No `sed` rules, no hardcoded version numbers in the tool itself.

---

## `boringssl_const.h` and `boringssl_masterkey.h` — the adaptive headers

These two headers already contain **all version-specific logic as pure C
preprocessor conditionals**.  They require no manual edits when a new Android
version is supported, provided the offset tool emits the correct feature flags.

### `boringssl_const.h` — TLS 1.3 secret offsets

Uses `#ifdef SSL_SESSION_ST_SSL_VERSION` (the Android 16+ feature flag) to
select between two offset formulas for the `SSL_HANDSHAKE` TLS 1.3 secret
fields:

| | Android ≤ 15 | Android 16+ |
|---|---|---|
| Secret storage type | `private uint8_t secret_[48]` | `public InplaceVector<uint8_t,48>` |
| Field step size | 48 bytes | 49 bytes (`SSL_HANDSHAKE_FIELD_STEP`) |
| `SSL_HANDSHAKE_SECRET_` base | `roundup(MAX_VERSION+2, 8) + 8` | `MAX_VERSION + 2` |
| `SSL_HANDSHAKE_HASH_LEN_` | separate `size_t hash_len_` field | `secret.size_` at `SECRET_ + 48` |

All 6 downstream field offsets (`EARLY_TRAFFIC_SECRET_`, etc.) are computed
with a single shared formula `SECRET_ + FIELD_STEP * N`, requiring no
duplication.

### `boringssl_masterkey.h` — TLS version detection

Uses two feature flags to work correctly on all Android versions:

- `#ifndef SSL_SESSION_ST_SSL_VERSION` — Android ≤ 15: reads TLS version from
  `ssl_st.version`.
- `#ifdef BSSL__SSL3_STATE_VERSION` — Android 16+: reads TLS version from
  `SSL3_STATE.version` (offset `0xd0`), **before** the TLS 1.2 / 1.3 branch
  decision, so TLS 1.3 connections are correctly identified.
- `#ifdef SSL_SESSION_ST_SSL_VERSION` — inside the TLS 1.2 block, re-reads
  version from `ssl_session_st.ssl_version` for accurate reporting.

---

## Notes and caveats

- **Network access**: `git fetch --tags` is attempted at startup; if the
  network is unavailable the script continues with locally cached branches.
- **Architecture**: offsets are architecture-specific.  The tool must be
  compiled and run on the **same CPU architecture** as the target device
  (e.g. aarch64 for Android ARM64 devices).  Cross-architecture offset
  generation will produce wrong values.
- **Duplicate definitions**: the shell script no longer appends any hardcoded
  `#define` after the tool output.  All defines come exclusively from the
  tool.  Editing the tool output by hand will cause drift; regenerate instead.
- **`boringssl-offset.c` requires C++17**: the `-std=c++17` flag is mandatory
  for `std::void_t`.  The script passes it automatically.

