// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Compile: g++ -std=c++17 -Wno-invalid-offsetof -I include/ -I . -I ./src/ offset.c -o offset
//
// This tool auto-detects BoringSSL struct layout changes across Android
// versions using C++ type traits + explicit template specialisation, so no
// external sed post-processing is needed when a new Android release removes or
// renames a field.
//
// Why template specialisation (not if constexpr)?
//   if constexpr in a non-template function still compiles *both* branches
//   syntactically, so offsetof on a removed field would be a hard error even
//   in the untaken branch.  Explicit template specialisation guarantees that
//   only the selected specialisation is instantiated and compiled.
//
// How the feature flags work:
//   The "false" specialisation (field absent) emits an *alternative* macro
//   (e.g. SSL_SESSION_ST_SSL_VERSION, BSSL__SSL3_STATE_VERSION, or the 0xFF
//   sentinel) that also doubles as a feature flag read by boringssl_const.h
//   and boringssl_masterkey.h to switch to the correct code path.

#include <ctype.h>
#include <openssl/base.h>
#include <openssl/crypto.h>
#include <ssl/internal.h>
#include <crypto/bio/internal.h>  // bio_st, bio_method_st (opaque in public headers; -I ./src/)
#include <stddef.h>
#include <stdio.h>
#include <type_traits>

// ─── Type-trait probes ───────────────────────────────────────────────────────
// Each probe checks whether a named public field exists on type T.
// A removed or private field causes substitution failure → false_type.

// ssl_st::version  (present in Android ≤ 15, removed in Android 16)
template <typename T, typename = void>
struct ssl_st_has_version : std::false_type {};
template <typename T>
struct ssl_st_has_version<T, std::void_t<decltype(std::declval<T>().version)>> : std::true_type {};

// ssl_session_st::secret_length  (present in Android ≤ 15, removed in Android 16)
template <typename T, typename = void>
struct ssl_session_has_secret_length : std::false_type {};
template <typename T>
struct ssl_session_has_secret_length<T, std::void_t<decltype(std::declval<T>().secret_length)>>
    : std::true_type {};

// bssl::SSL3_STATE::version  (absent in Android ≤ 15, added in Android 16)
template <typename T, typename = void>
struct ssl3_state_has_version : std::false_type {};
template <typename T>
struct ssl3_state_has_version<T, std::void_t<decltype(std::declval<T>().version)>>
    : std::true_type {};

// ssl_cipher_st::id  (uint32 in Android <=16; renamed to protocol_id/uint16 in Android 17)
template <typename T, typename = void>
struct ssl_cipher_has_id : std::false_type {};
template <typename T>
struct ssl_cipher_has_id<T, std::void_t<decltype(std::declval<T>().id)>> : std::true_type {};

// ─── Output helpers ──────────────────────────────────────────────────────────

void toUpper(const char *s) {
    for (int i = 0; s[i] != '\0'; i++) {
        if (s[i] == '.' || s[i] == ':') putchar('_');
        else putchar(toupper((unsigned char)s[i]));
    }
}

void format(const char *struct_name, const char *field_name, size_t offset) {
    printf("// %s->%s\n#define ", struct_name, field_name);
    toUpper(struct_name);
    putchar('_');
    toUpper(field_name);
    printf(" 0x%lx\n\n", offset);
}

// ─── Per-field emitters (partial template specialisation) ────────────────────
// Pattern: emit_xxx<T, Present>
//   Primary template (Present=false): field absent → emit alternative/sentinel.
//   Partial specialisation <T, true>:  field present → emit real offsetof(T,…).
//
// Why partial specialisation, not full specialisation?
//   Full specialisation bodies are compiled immediately.  Partial specialisation
//   bodies contain a *dependent* expression (offsetof(T, field)) that is only
//   checked when the specialisation is instantiated with a concrete T.
//   This ensures offsetof is never evaluated for a field that doesn't exist.

// --- ssl_st::version ---------------------------------------------------------
// Absent  → emit SSL_SESSION_ST_SSL_VERSION (Android 16+ feature flag).
// Present → emit SSL_ST_VERSION.
template <typename T, bool Present>
struct emit_ssl_st_version {
    static void emit() {
        printf("// ssl_st->version removed in this BoringSSL version.\n");
        printf("// SSL_SESSION_ST_SSL_VERSION also acts as the Android 16+ feature flag\n");
        printf("// for boringssl_const.h (InplaceVector offsets) and boringssl_masterkey.h.\n");
        format("ssl_session_st", "ssl_version", offsetof(ssl_session_st, ssl_version));
    }
};
template <typename T>
struct emit_ssl_st_version<T, true> {
    // offsetof(T, version) is a dependent expression: only compiled when T is known.
    static void emit() { format("ssl_st", "version", offsetof(T, version)); }
};

// --- ssl_session_st::secret_length -------------------------------------------
// Absent  → emit sentinel 0xFF (signals boringssl_masterkey.h to use the max).
// Present → emit the real offset.
template <typename T, bool Present>
struct emit_secret_length {
    static void emit() {
        printf("// ssl_session_st->secret_length removed in this BoringSSL version.\n");
        printf("// Sentinel 0xFF: boringssl_masterkey.h uses BORINGSSL_SSL_MAX_MASTER_KEY_LENGTH.\n");
        printf("#define SSL_SESSION_ST_SECRET_LENGTH 0xFF\n\n");
    }
};
template <typename T>
struct emit_secret_length<T, true> {
    static void emit() {
        format("ssl_session_st", "secret_length", offsetof(T, secret_length));
    }
};

// --- bssl::SSL3_STATE::version -----------------------------------------------
// Absent  → nothing to emit (field didn't exist before Android 16).
// Present → emit BSSL__SSL3_STATE_VERSION (Android 16+ feature flag).
//           boringssl_masterkey.h reads it before the TLS 1.2/1.3 branch so
//           that TLS 1.3 connections are correctly identified.
template <typename T, bool Present>
struct emit_ssl3_state_version {
    static void emit() { /* field not present in this version, nothing to emit */ }
};
// --- bssl::SSL3_STATE TLS 1.3 traffic secrets (Android 16+ InplaceVector layout) -------
// write_traffic_secret / read_traffic_secret / exporter_secret are consecutive
// InplaceVector<uint8_t,SSL_MAX_MD_SIZE> (48 bytes storage + 1 size_ byte). eCapture reads
// them in uretprobe_bssl_do_handshake via BSSL__SSL3_STATE_{SERVER,CLIENT}_TRAFFIC_SECRET_0
// (+ _LEN size_ byte). Emit them here so the values track the struct instead of being
// hand-maintained; the *_LEN offset is (next vector's offset) - 1, robust to any padding.
// Absent on Android <=15 (private raw arrays) -> emit nothing; masterkey.h defaults apply.
template <typename T, bool Present>
struct emit_ssl3_traffic_secrets {
    static void emit() { /* Android <=15: not public; nothing to emit */ }
};
template <typename T>
struct emit_ssl3_traffic_secrets<T, true> {
    static void emit() {
        size_t w = offsetof(T, write_traffic_secret);
        size_t r = offsetof(T, read_traffic_secret);
        size_t e = offsetof(T, exporter_secret);
        printf("// bssl::SSL3_STATE->write_traffic_secret (labelled SERVER_TRAFFIC_SECRET_0)\n");
        printf("#define BSSL__SSL3_STATE_SERVER_TRAFFIC_SECRET_0 0x%lx\n\n", w);
        printf("// bssl::SSL3_STATE->read_traffic_secret (labelled CLIENT_TRAFFIC_SECRET_0)\n");
        printf("#define BSSL__SSL3_STATE_CLIENT_TRAFFIC_SECRET_0 0x%lx\n\n", r);
        printf("// InplaceVector size_ bytes (== next vector offset - 1)\n");
        printf("#define BSSL__SSL3_STATE_SERVER_TRAFFIC_SECRET_0_LEN 0x%lx\n\n", r - 1);
        printf("#define BSSL__SSL3_STATE_CLIENT_TRAFFIC_SECRET_0_LEN 0x%lx\n\n", e - 1);
    }
};

template <typename T>
struct emit_ssl3_state_version<T, true> {
    static void emit() {
        printf("// SSL3_STATE->version added in Android 16 (replaces ssl_st->version).\n");
        printf("// BSSL__SSL3_STATE_VERSION is the Android 16+ feature flag used by\n");
        printf("// boringssl_masterkey.h to read the TLS version before the 1.2/1.3 branch.\n");
        format("bssl::SSL3_STATE", "version", offsetof(T, version));
    }
};

// --- ssl_cipher_st::id -------------------------------------------------------
// Present (Android <=16) -> emit SSL_CIPHER_ST_ID = offsetof(id) (uint32).
// Absent  (Android 17+)  -> field renamed to protocol_id (uint16); emit the same
// SSL_CIPHER_ST_ID macro at offsetof(protocol_id) so downstream kern code is stable.
template <typename T, bool Present>
struct emit_cipher_id {
    static void emit() { format("ssl_cipher_st", "id", offsetof(T, protocol_id)); }
};
template <typename T>
struct emit_cipher_id<T, true> {
    static void emit() { format("ssl_cipher_st", "id", offsetof(T, id)); }
};

// ─── Main ────────────────────────────────────────────────────────────────────

int main() {
    printf("/* OPENSSL_VERSION_TEXT: %s */\n", OPENSSL_VERSION_TEXT);
    printf("/* OPENSSL_VERSION_NUMBER: %d */\n\n", OPENSSL_VERSION_NUMBER);

    // ── ssl_st ────────────────────────────────────────────────────────────────
    emit_ssl_st_version<ssl_st, ssl_st_has_version<ssl_st>::value>::emit();
    format("ssl_st", "session", offsetof(ssl_st, session));
    format("ssl_st", "rbio",    offsetof(ssl_st, rbio));
    format("ssl_st", "wbio",    offsetof(ssl_st, wbio));
    format("ssl_st", "s3",      offsetof(ssl_st, s3));

    // ── ssl_session_st ────────────────────────────────────────────────────────
    emit_secret_length<ssl_session_st, ssl_session_has_secret_length<ssl_session_st>::value>::emit();
    format("ssl_session_st", "secret", offsetof(ssl_session_st, secret));
    format("ssl_session_st", "cipher", offsetof(ssl_session_st, cipher));

    // ── bio / cipher ──────────────────────────────────────────────────────────
    format("bio_st",        "num",    offsetof(bio_st, num));
    format("bio_st",        "method", offsetof(bio_st, method));
    format("bio_method_st", "type",   offsetof(bio_method_st, type));
    emit_cipher_id<ssl_cipher_st, ssl_cipher_has_id<ssl_cipher_st>::value>::emit();

    // ── bssl::SSL3_STATE ──────────────────────────────────────────────────────
    format("bssl::SSL3_STATE", "hs",                  offsetof(bssl::SSL3_STATE, hs));
    format("bssl::SSL3_STATE", "client_random",       offsetof(bssl::SSL3_STATE, client_random));
    format("bssl::SSL3_STATE", "exporter_secret",     offsetof(bssl::SSL3_STATE, exporter_secret));
    format("bssl::SSL3_STATE", "established_session", offsetof(bssl::SSL3_STATE, established_session));
    emit_ssl3_state_version<bssl::SSL3_STATE, ssl3_state_has_version<bssl::SSL3_STATE>::value>::emit();
    emit_ssl3_traffic_secrets<bssl::SSL3_STATE, ssl3_state_has_version<bssl::SSL3_STATE>::value>::emit();

    // ── ssl_st role bit (client vs server) ────────────────────────────────────
    // ssl_st.server is a bool bitfield (can't offsetof directly). It is the first
    // bitfield right after renegotiate_mode (an enum), so its byte = offsetof(
    // renegotiate_mode) + sizeof(enum). eCapture reads this byte and masks 0x1 to map
    // write/read_traffic_secret to the correct absolute CLIENT/SERVER NSS keylog labels.
    printf("// ssl_st->server (bool:1) byte — mask 0x1; 1=server endpoint, 0=client\n");
    printf("#define BSSL__SSL_ST_SERVER 0x%lx\n\n",
           offsetof(ssl_st, renegotiate_mode) + sizeof(ssl_renegotiate_mode_t));

    // ── bssl::SSL_HANDSHAKE ───────────────────────────────────────────────────
    // TLS 1.3 secret offsets (secret_, early_traffic_secret_, …) are NOT emitted
    // here; boringssl_const.h computes them from BSSL__SSL_HANDSHAKE_MAX_VERSION
    // with the correct per-version step (48 for raw arrays, 49 for InplaceVectors).
    format("bssl::SSL_HANDSHAKE", "new_session",    offsetof(bssl::SSL_HANDSHAKE, new_session));
    format("bssl::SSL_HANDSHAKE", "early_session",  offsetof(bssl::SSL_HANDSHAKE, early_session));
    format("bssl::SSL_HANDSHAKE", "hints",          offsetof(bssl::SSL_HANDSHAKE, hints));
    format("bssl::SSL_HANDSHAKE", "client_version", offsetof(bssl::SSL_HANDSHAKE, client_version));
    format("bssl::SSL_HANDSHAKE", "state",          offsetof(bssl::SSL_HANDSHAKE, state));
    format("bssl::SSL_HANDSHAKE", "tls13_state",    offsetof(bssl::SSL_HANDSHAKE, tls13_state));
    format("bssl::SSL_HANDSHAKE", "max_version",    offsetof(bssl::SSL_HANDSHAKE, max_version));

    return 0;
}
