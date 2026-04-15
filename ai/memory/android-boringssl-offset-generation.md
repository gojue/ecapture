# Android BoringSSL Offset Generation Methodology

## Purpose

This document describes the step-by-step methodology for generating eBPF struct offset headers when a **new Android version** ships with a **new BoringSSL** that changes internal struct layouts.  eCapture's TLS key capture on Android depends on hardcoded byte offsets into BoringSSL's private C++ structs (`ssl_st`, `ssl_session_st`, `bssl::SSL_HANDSHAKE`, `bssl::SSL3_STATE`, etc.). When Google updates BoringSSL for a new Android release, those offsets may shift and must be regenerated.

> **Important**: Do NOT reference `utils/boringssl_non_android_offset.sh` — that script is for non-Android (upstream) BoringSSL and has different struct layouts and branches.

---

## Prerequisites

- Linux x86_64 build host with `g++`, `git`
- Access to `https://android.googlesource.com/platform/external/boringssl`
- Repository cloned at project root (`go.mod` present)

---

## Step 1: Clone the Android BoringSSL Repository

```bash
# From project root
BORINGSSL_REPO=https://android.googlesource.com/platform/external/boringssl
BORINGSSL_DIR="./deps/boringssl"
git clone ${BORINGSSL_REPO} ${BORINGSSL_DIR}
```

Reference: `utils/boringssl_android_offset.sh` lines 1–20.

---

## Step 2: Check Out the Target Android Release Branch

Android BoringSSL branches follow the naming convention `android${VERSION}-release`:

```bash
cd ${BORINGSSL_DIR}
git fetch --tags
git checkout android16-release   # or android17-release, etc.
```

Also check out the **previous** version's branch (e.g., `android15-release`) to compare structs.

---

## Step 3: Identify Struct Differences

The key file is `src/ssl/internal.h`. Compare it between the two branches:

```bash
# From deps/boringssl
git diff android15-release..android16-release -- src/ssl/internal.h
```

### Structs to Check

| Struct | Header Reference | Key Fields for eCapture |
|---|---|---|
| `ssl_st` | `src/ssl/internal.h` | `version`, `session`, `rbio`, `wbio`, `s3` |
| `ssl_session_st` | `src/ssl/internal.h` | `ssl_version` (or `secret_length` in older), `secret`, `cipher` |
| `bssl::SSL3_STATE` | `src/ssl/internal.h` | `hs`, `client_random`, `exporter_secret`, `established_session` |
| `bssl::SSL_HANDSHAKE` | `src/ssl/internal.h` | `new_session`, `early_session`, `hints`, `client_version`, `state`, `tls13_state`, `max_version`, and TLS 1.3 secret fields |
| `bio_st` | `src/ssl/internal.h` or `include/openssl/bio.h` | `num`, `method` |
| `bio_method_st` | `include/openssl/bio.h` | `type` |
| `ssl_cipher_st` | `src/ssl/internal.h` | `id` |

### Common Breaking Changes to Watch For

1. **Field type changes**: e.g., `uint8_t secret_[48]` → `InplaceVector<uint8_t, 48>` (49 bytes instead of 48)
2. **Field removal**: e.g., `hash_len_` removed, `ssl_st.version` removed, `secret_length` removed
3. **Field addition**: e.g., new `ssl_version` field in `ssl_session_st`
4. **Field reordering**: Any reordering shifts all subsequent field offsets
5. **Type size changes**: e.g., `InplaceVector` adds a `size_` byte per field

---

## Step 4: Create the Offset Source File

### If the struct layout is **compatible** with the previous version

Use the existing `utils/boringssl-offset.c` (the generic Android offset calculator).

### If the struct layout has **breaking changes**

Create a new dedicated offset file, e.g., `utils/boringssl-android16-offset.c`.

The offset source file uses the C++ `offsetof()` macro against BoringSSL headers:

```c
#include <openssl/base.h>
#include <openssl/crypto.h>
#include <ssl/internal.h>
#include <stddef.h>
#include <stdio.h>

// Define X-macro lists for standard and changed fields
#define SSL_STRUCT_OFFSETS  \
    X(ssl_st, session)     \
    X(ssl_st, rbio)        \
    // ... etc

#define X(struct_name, field_name) \
    format(#struct_name, #field_name, offsetof(struct struct_name, field_name));
    SSL_STRUCT_OFFSETS
#undef X
```

Key considerations:
- If `ssl_st.version` was removed, do NOT include `X(ssl_st, version)` in the list
- If `ssl_session_st.secret_length` was replaced by `ssl_session_st.ssl_version`, update accordingly
- For `InplaceVector`-based fields, add them as separate offsetof() entries since they are now public fields

Compile and run:
```bash
g++ -Wno-write-strings -Wno-invalid-offsetof \
    -I include/ -I . -I ./src/ offset.c -o offset
./offset
```

---

## Step 5: Generate the Kern Header File

The offset program's stdout produces `#define` directives. Wrap them in a header guard:

```bash
HEADER_FILE="kern/boringssl_a_${VERSION}_kern.c"
echo "#ifndef ECAPTURE_BORINGSSL_A_${VERSION}_KERN_H" > ${HEADER_FILE}
echo "#define ECAPTURE_BORINGSSL_A_${VERSION}_KERN_H"  >> ${HEADER_FILE}
./offset >> ${HEADER_FILE}
```

### Handle Version-Specific Differences

For versions with breaking changes, add sentinel defines BEFORE the `#include` directives:

```c
// If secret_length field was removed:
#define SSL_SESSION_ST_SECRET_LENGTH 0xFF

// If TLS 1.3 secrets use InplaceVector instead of raw arrays:
#define BORINGSSL_INPLACEVECTOR_SECRETS

// If hash_len_ field was removed (read from InplaceVector.size_ instead):
#define BSSL__SSL_HANDSHAKE_HASH_LEN (BSSL__SSL_HANDSHAKE_SECRET+0x30)
```

Then add the standard includes:
```c
#include "boringssl_const.h"
#include "boringssl_masterkey.h"
#include "openssl.h"

#endif
```

---

## Step 6: Update boringssl_const.h (if needed)

`kern/boringssl_const.h` derives TLS 1.3 secret offsets from the `max_version` offset.

If the new Android version changes how secrets are laid out (e.g., InplaceVector), add a conditional:

```c
#ifdef BORINGSSL_INPLACEVECTOR_SECRETS
// Use pre-computed offsets from the kern header directly
#define SSL_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_SECRET
#define SSL_HANDSHAKE_EARLY_TRAFFIC_SECRET_ BSSL__SSL_HANDSHAKE_EARLY_TRAFFIC_SECRET
// ... etc
#else
// Original computation from max_version offset
#define SSL_HANDSHAKE_HASH_LEN_ roundup(BSSL__SSL_HANDSHAKE_MAX_VERSION+2,8)
#define SSL_HANDSHAKE_SECRET_ SSL_HANDSHAKE_HASH_LEN_+8
// ... etc
#endif
```

---

## Step 7: Update boringssl_masterkey.h (if needed)

Check that `kern/boringssl_masterkey.h` handles:
- Reading TLS version from the new location (e.g., `SSL_SESSION_ST_SSL_VERSION` instead of `SSL_ST_VERSION`)
- Fixed master key length when `secret_length` is removed (use `BORINGSSL_SSL_MAX_MASTER_KEY_LENGTH`)
- Hash length from InplaceVector's `size_` field instead of `hash_len_`

Use `#ifdef` guards for version-specific code paths, keyed on defines from the kern header (e.g., `SSL_SESSION_ST_SSL_VERSION`).

---

## Step 8: Update boringssl_android_offset.sh

Add the new Android version to the `sslVerMap` in `utils/boringssl_android_offset.sh`:

```bash
sslVerMap["4"]="16"  # android16-release
```

Add conditional logic to use the dedicated offset source file:

```bash
if (( val > 15 )); then
    cp -f ${PROJECT_ROOT_DIR}/utils/boringssl-android16-offset.c ${BORINGSSL_DIR}/offset.c
else
    cp -f ${PROJECT_ROOT_DIR}/utils/boringssl-offset.c ${BORINGSSL_DIR}/offset.c
fi
```

---

## Step 9: Verify

1. **Offset program compiles and runs**:
   ```bash
   cd deps/boringssl && git checkout android${VERSION}-release
   cp ../utils/boringssl-android${VERSION}-offset.c offset.c
   g++ -Wno-write-strings -Wno-invalid-offsetof -I include/ -I . -I ./src/ offset.c -o offset
   ./offset  # Should print #define lines
   ```

2. **Generated kern header matches expected offsets**: Cross-reference offsets with `offsetof()` calculations manually or via a test program.

3. **Go build succeeds**:
   ```bash
   go build ./...
   ```

4. **Go tests pass**:
   ```bash
   go test ./internal/... ./pkg/... ./cli/...
   ```

---

## Offset Verification Checklist

When verifying offsets, check these critical fields:

- [ ] `ssl_st->s3` — pointer to SSL3_STATE (used to chain to handshake state)
- [ ] `ssl_st->session` — pointer to ssl_session_st (TLS 1.2 master secret)
- [ ] `bssl::SSL3_STATE->hs` — pointer to SSL_HANDSHAKE (TLS 1.3 secrets)
- [ ] `bssl::SSL3_STATE->client_random` — 32 bytes, must be correct for keylog
- [ ] `bssl::SSL3_STATE->exporter_secret` — TLS 1.3 exporter
- [ ] `bssl::SSL_HANDSHAKE->state/tls13_state` — handshake state machine values
- [ ] `bssl::SSL_HANDSHAKE->secret` through `expected_client_finished` — TLS 1.3 secret fields (stride matters!)
- [ ] `ssl_session_st->secret` — TLS 1.2 master secret data
- [ ] `ssl_session_st->cipher` — cipher suite pointer

---

## Common Pitfalls

1. **Do not use `boringssl_non_android_offset.sh`** — it targets upstream BoringSSL from `boringssl.googlesource.com`, which has a completely different struct layout than Android's fork at `android.googlesource.com`.

2. **InplaceVector stride is 49, not 48** — When BoringSSL replaces `uint8_t[48]` with `InplaceVector<uint8_t, 48>`, each field is 49 bytes (48 data + 1 byte `size_`). Using 48-byte stride will cause cumulative offset drift.

3. **Private fields cannot use `offsetof()` directly** — BoringSSL's TLS 1.3 secret arrays are in a `private:` section. In older versions, compute them relative to `max_version`. In newer versions with InplaceVector, they may be public and `offsetof()` works.

4. **PAC (Pointer Authentication Code) is NOT the root cause of Android version upgrade issues** — When ecapture fails on a new Android version, the root cause is almost always **wrong struct offsets**, not PAC pointer masking. PAC may co-exist on ARM64 devices but does not cause the "only captures responses, not requests" or "keylog doesn't work" symptoms. Those symptoms are caused by reading TLS 1.3 secrets from incorrect memory addresses due to struct layout changes. Do NOT add PAC stripping code as a fix for offset problems.

5. **Always download and analyze actual source code** — Never guess offsets. Always clone the BoringSSL branch and compile the offset program against its headers.

---

## File Reference

| File | Purpose |
|---|---|
| `kern/boringssl_a_${VER}_kern.c` | Per-Android-version offset defines |
| `kern/boringssl_const.h` | Computes TLS 1.3 secret offsets from base offset |
| `kern/boringssl_masterkey.h` | eBPF program that reads TLS secrets using offsets |
| `utils/boringssl-offset.c` | Generic Android offset calculator (≤A15) |
| `utils/boringssl-android16-offset.c` | Android 16+ offset calculator (InplaceVector) |
| `utils/boringssl_android_offset.sh` | Orchestration script for offset generation |
| `kern/common.h` | Common eBPF defines (pid/uid filtering, etc.) |
