#ifndef ECAPTURE_OPENSSL_3_0_1_KERN_H
#define ECAPTURE_OPENSSL_3_0_1_KERN_H

/* OPENSSL_VERSION_TEXT: OpenSSL 3.0.1 14 Dec 2021, OPENSSL_VERSION_NUMBER: 805306384 */

// ssl_st->version
#define SSL_ST_VERSION 0x0

// ssl_st->session
#define SSL_ST_SESSION 0x918

// ssl_st->s3
#define SSL_ST_S3 0xa8

// ssl_session_st->master_key
#define SSL_SESSION_ST_MASTER_KEY 0x50

// ssl_st->s3.client_random
#define SSL_ST_S3_CLIENT_RANDOM 0x160

// ssl_session_st->cipher
#define SSL_SESSION_ST_CIPHER 0x2f8

// ssl_session_st->cipher_id
#define SSL_SESSION_ST_CIPHER_ID 0x300

// ssl_cipher_st->id
#define SSL_CIPHER_ST_ID 0x18

// ssl_st->handshake_secret
#define SSL_ST_HANDSHAKE_SECRET 0x584

// ssl_st->master_secret
#define SSL_ST_MASTER_SECRET 0x5c4

// ssl_st->server_finished_hash
#define SSL_ST_SERVER_FINISHED_HASH 0x6c4

// ssl_st->handshake_traffic_hash
#define SSL_ST_HANDSHAKE_TRAFFIC_HASH 0x704

// ssl_st->exporter_master_secret
#define SSL_ST_EXPORTER_MASTER_SECRET 0x7c4

#include "openssl.h"
#include "openssl_masterkey_3.0.h"

#endif

