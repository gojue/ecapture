#ifndef ECAPTURE_OPENSSL_3_0_6_KERN_H
#define ECAPTURE_OPENSSL_3_0_6_KERN_H

/* OPENSSL_VERSION_TEXT: OpenSSL 3.1.6 4 Jun 2024 */
/* OPENSSL_VERSION_NUMBER: 806355040 */

// ssl_st->version
#define SSL_ST_VERSION 0x0

// ssl_st->session
#define SSL_ST_SESSION 0x918

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

// ssl_st->handshake_traffic_hash
#define SSL_ST_HANDSHAKE_TRAFFIC_HASH 0x704

// ssl_st->client_app_traffic_secret
#define SSL_ST_CLIENT_APP_TRAFFIC_SECRET 0x744

// ssl_st->server_app_traffic_secret
#define SSL_ST_SERVER_APP_TRAFFIC_SECRET 0x784

// ssl_st->exporter_master_secret
#define SSL_ST_EXPORTER_MASTER_SECRET 0x7c4

// bio_st->num
#define BIO_ST_NUM 0x38

#include "openssl.h"
#include "openssl_masterkey_3.0.h"

#endif
