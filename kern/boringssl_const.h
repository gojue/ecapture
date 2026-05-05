// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#pragma once

/////////////////////////////////////////// DON'T REMOVE THIS CODE BLOCK. //////////////////////////////////////////
// SSL_MAX_MD_SIZE is size of the largest hash function used in TLS, SHA-384.
#define SSL_MAX_MD_SIZE 48

// memory layout from boringssl repo  ssl/internal.h
// struct SSL_HANDSHAKE
//
// ── Android ≤ 15  (TLS 1.3 secrets are private raw arrays) ─────────────────
//   uint16_t max_version;          // public,  2 bytes  @ BSSL__SSL_HANDSHAKE_MAX_VERSION
//   // private (aligned to 8):
//   size_t   hash_len_;            // 8 bytes
//   uint8_t  secret_[48];          // 48 bytes  ← SSL_HANDSHAKE_SECRET_
//   uint8_t  early_traffic_secret_[48];         // step = 48
//   ...
//
// ── Android 16+  (TLS 1.3 secrets are public InplaceVector<uint8_t,48>) ────
//   uint16_t max_version;          // public, 2 bytes
//   InplaceVector<uint8_t,48> secret;           // ← SSL_HANDSHAKE_SECRET_
//   InplaceVector<uint8_t,48> early_traffic_secret;  // step = 49
//   ...
//
// InplaceVector<uint8_t,N> memory layout (alignof=1, no padding):
//   [0 .. N-1] storage_[N]  — actual data bytes  (same address as struct base)
//   [N]        size_         — uint8_t            (equivalent of hash_len_)
//
// SSL_SESSION_ST_SSL_VERSION is defined only in android16 kern headers and
// serves as the version feature-flag here.
// ────────────────────────────────────────────────────────────────────────────

#ifdef SSL_SESSION_ST_SSL_VERSION
// ── Android 16+: three root values differ from older versions ───────────────

// secret.storage_ starts right after max_version (alignof InplaceVector = 1, no gap)
#define SSL_HANDSHAKE_SECRET_    (BSSL__SSL_HANDSHAKE_MAX_VERSION + 2)

// hash_len is now secret.size_: the uint8_t sitting right after secret.storage_[48]
#define SSL_HANDSHAKE_HASH_LEN_  (SSL_HANDSHAKE_SECRET_ + SSL_MAX_MD_SIZE)

// Each InplaceVector<uint8_t,48> occupies 49 bytes (48 data + 1 size_)
#define SSL_HANDSHAKE_FIELD_STEP (SSL_MAX_MD_SIZE + 1)

#else
// ── Android ≤ 15: original layout ───────────────────────────────────────────

// hash_len_ is a size_t aligned to 8, sitting right after max_version
#define SSL_HANDSHAKE_HASH_LEN_  roundup(BSSL__SSL_HANDSHAKE_MAX_VERSION + 2, 8)

// secret_ follows hash_len_ (size_t = 8 bytes)
#define SSL_HANDSHAKE_SECRET_    (SSL_HANDSHAKE_HASH_LEN_ + 8)

// Each raw uint8_t[48] field occupies exactly 48 bytes, no extra size field
#define SSL_HANDSHAKE_FIELD_STEP SSL_MAX_MD_SIZE

#endif  // SSL_SESSION_ST_SSL_VERSION

// ── Downstream offsets: identical formula for all versions ──────────────────
// All fields are laid out consecutively starting from SSL_HANDSHAKE_SECRET_,
// each spaced SSL_HANDSHAKE_FIELD_STEP bytes apart.

#define SSL_HANDSHAKE_EARLY_TRAFFIC_SECRET_     (SSL_HANDSHAKE_SECRET_ + SSL_HANDSHAKE_FIELD_STEP * 1)
#define SSL_HANDSHAKE_CLIENT_HANDSHAKE_SECRET_  (SSL_HANDSHAKE_SECRET_ + SSL_HANDSHAKE_FIELD_STEP * 2)
#define SSL_HANDSHAKE_SERVER_HANDSHAKE_SECRET_  (SSL_HANDSHAKE_SECRET_ + SSL_HANDSHAKE_FIELD_STEP * 3)
#define SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_  (SSL_HANDSHAKE_SECRET_ + SSL_HANDSHAKE_FIELD_STEP * 4)
#define SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_  (SSL_HANDSHAKE_SECRET_ + SSL_HANDSHAKE_FIELD_STEP * 5)
#define SSL_HANDSHAKE_EXPECTED_CLIENT_FINISHED_ (SSL_HANDSHAKE_SECRET_ + SSL_HANDSHAKE_FIELD_STEP * 6)

///////////////////////////  END   ///////////////////////////
