#ifndef ECAPTURE_OPENSSL_1_1_1_J_KERN_H
#define ECAPTURE_OPENSSL_1_1_1_J_KERN_H

/* OPENSSL_VERSION_TEXT: OpenSSL 1.1.1w  11 Sep 2023 */
/* OPENSSL_VERSION_NUMBER: 269488511 */

// ssl_st->version
#define SSL_ST_VERSION 0x0

// ssl_st->session
#define SSL_ST_SESSION 0x510

// ssl_st->s3
#define SSL_ST_S3 0xa8

// ssl_st->rbio
#define SSL_ST_RBIO 0x10

// ssl_st->wbio
#define SSL_ST_WBIO 0x18

// ssl_st->server
#define SSL_ST_SERVER 0x38

// ssl_session_st->master_key
#define SSL_SESSION_ST_MASTER_KEY 0x50

// ssl3_state_st->client_random
#define SSL3_STATE_ST_CLIENT_RANDOM 0xb8

// ssl_session_st->cipher
#define SSL_SESSION_ST_CIPHER 0x1f0

// ssl_session_st->cipher_id
#define SSL_SESSION_ST_CIPHER_ID 0x1f8

// ssl_cipher_st->id
#define SSL_CIPHER_ST_ID 0x18

// ssl_st->early_secret
#define SSL_ST_EARLY_SECRET 0x13c

// ssl_st->handshake_secret
#define SSL_ST_HANDSHAKE_SECRET 0x17c

// ssl_st->handshake_traffic_hash
#define SSL_ST_HANDSHAKE_TRAFFIC_HASH 0x2fc

// ssl_st->client_app_traffic_secret
#define SSL_ST_CLIENT_APP_TRAFFIC_SECRET 0x33c

// ssl_st->server_app_traffic_secret
#define SSL_ST_SERVER_APP_TRAFFIC_SECRET 0x37c

// ssl_st->exporter_master_secret
#define SSL_ST_EXPORTER_MASTER_SECRET 0x3bc

// bio_st->num
#define BIO_ST_NUM 0x30

// bio_st->method
#define BIO_ST_METHOD 0x0

// bio_method_st->type
#define BIO_METHOD_ST_TYPE 0x0

#include "openssl.h"
#include "openssl_masterkey.h"

#endif
