#ifndef ECAPTURE_OPENSSL_1_1_1_F_KERN_H
#define ECAPTURE_OPENSSL_1_1_1_F_KERN_H

/* OPENSSL_VERSION_TEXT: OpenSSL 1.1.1f  31 Mar 2020, OPENSSL_VERSION_NUMBER: 269488239 */

// ssl_st->version
#define SSL_ST_VERSION 0x0

// ssl_st->session
#define SSL_ST_SESSION 0x510

// ssl_st->s3
#define SSL_ST_S3 0xa8

// ssl_session_st->master_key
#define SSL_SESSION_ST_MASTER_KEY 0x50

// ssl3_state_st->client_random
#define SSL3_STATE_ST_CLIENT_RANDOM 0xb8

// ssl_session_st->cipher
#define SSL_SESSION_ST_CIPHER 0x1f8

// ssl_session_st->cipher_id
#define SSL_SESSION_ST_CIPHER_ID 0x200

// ssl_cipher_st->id
#define SSL_CIPHER_ST_ID 0x18

// ssl_st->handshake_secret
#define SSL_ST_HANDSHAKE_SECRET 0x17c

// ssl_st->master_secret
#define SSL_ST_MASTER_SECRET 0x1bc

// ssl_st->server_finished_hash
#define SSL_ST_SERVER_FINISHED_HASH 0x2bc

// ssl_st->handshake_traffic_hash
#define SSL_ST_HANDSHAKE_TRAFFIC_HASH 0x2fc

// ssl_st->exporter_master_secret
#define SSL_ST_EXPORTER_MASTER_SECRET 0x3bc

#include "openssl.h"
#include "openssl_masterkey.h"

#endif

