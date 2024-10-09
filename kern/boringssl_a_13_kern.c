#ifndef ECAPTURE_BORINGSSL_A_13_KERN_H
#define ECAPTURE_BORINGSSL_A_13_KERN_H

/* OPENSSL_VERSION_TEXT: OpenSSL 1.1.1 (compatible; BoringSSL) */
/* OPENSSL_VERSION_NUMBER: 269488255 */

// ssl_st->version
#define SSL_ST_VERSION 0x10

// ssl_st->session
#define SSL_ST_SESSION 0x58

// ssl_st->rbio
#define SSL_ST_RBIO 0x18

// ssl_st->wbio
#define SSL_ST_WBIO 0x20

// ssl_st->s3
#define SSL_ST_S3 0x30

// ssl_session_st->secret_length
#define SSL_SESSION_ST_SECRET_LENGTH 0xc

// ssl_session_st->secret
#define SSL_SESSION_ST_SECRET 0x10

// ssl_session_st->cipher
#define SSL_SESSION_ST_CIPHER 0xd0

// bio_st->num
#define BIO_ST_NUM 0x18

// bio_st->method
#define BIO_ST_METHOD 0x0

// bio_method_st->type
#define BIO_METHOD_ST_TYPE 0x0

// ssl_cipher_st->id
#define SSL_CIPHER_ST_ID 0x10

// bssl::SSL3_STATE->hs
#define BSSL__SSL3_STATE_HS 0x110

// bssl::SSL3_STATE->client_random
#define BSSL__SSL3_STATE_CLIENT_RANDOM 0x30

// bssl::SSL3_STATE->exporter_secret
#define BSSL__SSL3_STATE_EXPORTER_SECRET 0x178

// bssl::SSL3_STATE->established_session
#define BSSL__SSL3_STATE_ESTABLISHED_SESSION 0x1c8

// bssl::SSL_HANDSHAKE->new_session
#define BSSL__SSL_HANDSHAKE_NEW_SESSION 0x5d8

// bssl::SSL_HANDSHAKE->early_session
#define BSSL__SSL_HANDSHAKE_EARLY_SESSION 0x5e0

// bssl::SSL_HANDSHAKE->hints
#define BSSL__SSL_HANDSHAKE_HINTS 0x610

// bssl::SSL_HANDSHAKE->client_version
#define BSSL__SSL_HANDSHAKE_CLIENT_VERSION 0x61c

// bssl::SSL_HANDSHAKE->state
#define BSSL__SSL_HANDSHAKE_STATE 0x14

// bssl::SSL_HANDSHAKE->tls13_state
#define BSSL__SSL_HANDSHAKE_TLS13_STATE 0x18

// bssl::SSL_HANDSHAKE->max_version
#define BSSL__SSL_HANDSHAKE_MAX_VERSION 0x1e

#include "boringssl_const.h"
#include "boringssl_masterkey.h"
#include "openssl.h"

#endif
