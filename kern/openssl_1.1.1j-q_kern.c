#ifndef ECAPTURE_OPENSSL_1_1_1_J_Q_H
#define ECAPTURE_OPENSSL_1_1_1_J_Q_H

/* OPENSSL_VERSION_TEXT: OpenSSL 1.1.1j  16 Feb 2021, OPENSSL_VERSION_NUMBER:269488303 */

// ssl->version 在 ssl_st 结构体中的偏移量
#define SSL_ST_VERSION 0x0

// ssl->session 在 ssl_st 结构中的偏移量
#define SSL_ST_SESSION 0x510

// ssl->s3 在 ssl_st中的偏移量
#define SSL_ST_S3 0xa8

// session->master_key 在 SSL_SESSION 中的偏移量
#define SSL_SESSION_ST_MASTER_KEY 0x50

// s3->client_random 在 ssl3_state_st 中的偏移量
#define SSL3_STATE_ST_CLIENT_RANDOM 0xb8

// session->cipher 在 SSL_SESSION 中的偏移量
#define SSL_SESSION_ST_CIPHER 0x1f0

// session->cipher_id 在 SSL_SESSION 中的偏移量
#define SSL_SESSION_ST_CIPHER_ID 0x1f8

// cipher->id 在 ssl_cipher_st 中的偏移量
#define SSL_CIPHER_ST_ID 0x18

// ssl->handshake_secret 在 ssl_st 中的偏移量
#define SSL_ST_HANDSHAKE_SECRET 0x17c

// ssl->master_secret 在 ssl_st 中的偏移量
#define SSL_ST_MASTER_SECRET 0x1bc

// ssl->server_finished_hash 在 ssl_st 中的偏移量
#define SSL_ST_SERVER_FINISHED_HASH 0x2bc

// ssl->handshake_traffic_hash 在 ssl_st 中的偏移量
#define SSL_ST_HANDSHAKE_TRAFFIC_HASH 0x2fc

// ssl->exporter_master_secret 在 ssl_st 中的偏移量
#define SSL_ST_EXPORTER_MASTER_SECRET 0x3bc

#endif

#include "openssl.h"
#include "openssl_masterkey.h"