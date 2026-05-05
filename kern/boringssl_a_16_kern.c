#ifndef ECAPTURE_BORINGSSL_A_16_KERN_H
#define ECAPTURE_BORINGSSL_A_16_KERN_H

/* OPENSSL_VERSION_TEXT: OpenSSL 1.1.1 (compatible; BoringSSL) */
/* OPENSSL_VERSION_NUMBER: 269488255 */

// ssl_st->session
#define SSL_ST_SESSION 0x58

// ssl_st->rbio
#define SSL_ST_RBIO 0x18

// ssl_st->wbio
#define SSL_ST_WBIO 0x20

// ssl_st->s3
#define SSL_ST_S3 0x30

// ssl_session_st->ssl_version
// NOTE: In Android 16, ssl_st no longer has a 'version' field.
// The version is now read from ssl_session_st->ssl_version instead.
// This macro also acts as the feature flag for boringssl_const.h to
// apply Android 16 InplaceVector-based TLS 1.3 secret offset formulas.
#define SSL_SESSION_ST_SSL_VERSION 0x4

// ssl_session_st->secret
// In Android 16, 'secret' is InplaceVector<uint8_t, SSL_MAX_MASTER_KEY_LENGTH>.
// InplaceVector stores storage_[] first, so data starts at the base offset.
#define SSL_SESSION_ST_SECRET 0xa

// ssl_session_st->cipher
#define SSL_SESSION_ST_CIPHER 0xc8

// bio_st->num
#define BIO_ST_NUM 0x20

// bio_st->method
#define BIO_ST_METHOD 0x0

// bio_method_st->type
#define BIO_METHOD_ST_TYPE 0x0

// ssl_cipher_st->id
#define SSL_CIPHER_ST_ID 0x10

// bssl::SSL3_STATE->hs
#define BSSL__SSL3_STATE_HS 0x118

// bssl::SSL3_STATE->client_random
#define BSSL__SSL3_STATE_CLIENT_RANDOM 0x30

// bssl::SSL3_STATE->version
// NOTE: In Android 16, ssl_st.version was removed. The protocol version is
// now stored here in SSL3_STATE. Used to correctly detect TLS 1.3 connections.
#define BSSL__SSL3_STATE_VERSION 0xd0

// bssl::SSL3_STATE->exporter_secret
#define BSSL__SSL3_STATE_EXPORTER_SECRET 0x182

// bssl::SSL3_STATE->established_session
#define BSSL__SSL3_STATE_ESTABLISHED_SESSION 0x1d0

// bssl::SSL_HANDSHAKE->new_session
#define BSSL__SSL_HANDSHAKE_NEW_SESSION 0x5f0

// bssl::SSL_HANDSHAKE->early_session
#define BSSL__SSL_HANDSHAKE_EARLY_SESSION 0x5f8

// bssl::SSL_HANDSHAKE->hints
#define BSSL__SSL_HANDSHAKE_HINTS 0x628

// bssl::SSL_HANDSHAKE->client_version
#define BSSL__SSL_HANDSHAKE_CLIENT_VERSION 0x634

// bssl::SSL_HANDSHAKE->state
#define BSSL__SSL_HANDSHAKE_STATE 0x14

// bssl::SSL_HANDSHAKE->tls13_state
#define BSSL__SSL_HANDSHAKE_TLS13_STATE 0x18

// bssl::SSL_HANDSHAKE->max_version
#define BSSL__SSL_HANDSHAKE_MAX_VERSION 0x1e

#define SSL_SESSION_ST_SECRET_LENGTH 0xFF

#include "boringssl_const.h"
#include "boringssl_masterkey.h"
#include "openssl.h"

#endif
