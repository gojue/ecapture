#ifndef ECAPTURE_BORINGSSL_1_1_1_H
#define ECAPTURE_BORINGSSL_1_1_1_H

/* OPENSSL_VERSION_TEXT: OpenSSL 1.1.1 (compatible; BoringSSL), OPENSSL_VERSION_NUMBER:0x1010107f */

//------------------------------------------
// android boringssl 版本
// ssl->version 在 ssl_st 结构体中的偏移量
#define SSL_ST_VERSION 16

// ssl->session 在 ssl_st 结构中的偏移量
#define SSL_ST_SESSION 88

// session->secret 在 SSL_SESSION 中的偏移量
#define SSL_SESSION_ST_MASTER_KEY 16

// ssl->s3 在 ssl_st中的偏移量
#define SSL_ST_S3 48

// s3->hs 在 ssl3_state_st 中的偏移量
#define SSL_HS_OFFSET 272

// hs->established_session 在 SSL_HANDSHAKE 中的偏移量
#define SSL_ESTABLISHED_SESSION_OFFSET 456

// hs->new_session 在 SSL_HANDSHAKE 中的偏移量
#define SSL_HS_NEW_SESSION_OFFSET 656

// hs->early_session 在 SSL_HANDSHAKE 中的偏移量
#define SSL_HS_EARLY_SESSION_OFFSET 664

// s3->client_random 在 ssl3_state_st 中的偏移量
#define SSL_S3_CLIENT_RANDOM_OFFSET 48


////////// TLS 1.2 or older /////////

// session->cipher 在 SSL_SESSION 中的偏移量
#define SSL_SESSION_ST_CIPHER 496

// session->cipher_id 在 SSL_SESSION 中的偏移量
#define SSL_SESSION_ST_CIPHER_ID 0x1f8

// cipher->id 在 ssl_cipher_st 中的偏移量
#define SSL_CIPHER_ST_ID 0x18

// ssl->handshake_secret 在 ssl_st 中的偏移量
#define SSL_ST_HANDSHAKE_SECRET 0x17C  // 380

// ssl->master_secret 在 ssl_st 中的偏移量
#define SSL_ST_MASTER_SECRET 0x1BC  // 444

// ssl->server_finished_hash 在 ssl_st 中的偏移量
#define SSL_ST_SERVER_FINISHED_SECRET 0x2BC  // 700

// ssl->handshake_traffic_hash 在 ssl_st 中的偏移量
#define SSL_ST_HANDSHAKE_TRAFFIC_HASH 0x2FC  // 764

// ssl->exporter_master_secret 在 ssl_st 中的偏移量
#define SSL_ST_EXPORTER_MASTER_SECRET 0x3BC  // 956

#endif

#include "openssl.h"