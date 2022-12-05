#ifndef ECAPTURE_BORINGSSL_1_1_1_H
#define ECAPTURE_BORINGSSL_1_1_1_H

/* OPENSSL_VERSION_TEXT: OpenSSL 1.1.1 (compatible; BoringSSL), OPENSSL_VERSION_NUMBER:0x1010107f */

//------------------------------------------
// android boringssl 版本
// ssl->version 在 ssl_st 结构体中的偏移量
#define SSL_ST_VERSION 0x10

// ssl->session 在 ssl_st 结构中的偏移量
#define SSL_ST_SESSION 0x58

// ssl->s3 在 ssl_st中的偏移量
#define SSL_ST_S3 0x30

// ssl_session_st->secret
#define SSL_SESSION_ST_SECRET 0x10

// ssl_session_st->secret_length
#define SSL_SESSION_ST_SECRET_LENGTH 0xc

// ssl_session_st->cipher
#define SSL_SESSION_ST_CIPHER 0xd0

// ssl_cipher_st->id
#define SSL_CIPHER_ST_ID 0x10

// bssl::SSL3_STATE->hs
#define BSSL__SSL3_STATE_HS 0x118

// bssl::SSL3_STATE->client_random
#define BSSL__SSL3_STATE_CLIENT_RANDOM 0x30

// bssl::SSL_HANDSHAKE->new_session
#define BSSL__SSL_HANDSHAKE_NEW_SESSION 0x5f0

// bssl::SSL_HANDSHAKE->early_session
#define BSSL__SSL_HANDSHAKE_EARLY_SESSION 0x5f8

// bssl::SSL3_STATE->established_session
#define BSSL__SSL3_STATE_ESTABLISHED_SESSION 0x1d0

// bssl::SSL_HANDSHAKE->max_version
#define BSSL__SSL_HANDSHAKE_MAX_VERSION 0x1e

// s3->established_session 在 SSL_HANDSHAKE 中的偏移量
#define SSL_ESTABLISHED_SESSION_OFFSET 456

// hs->new_session 在 SSL_HANDSHAKE 中的偏移量
#define SSL_HS_NEW_SESSION_OFFSET 656

// hs->early_session 在 SSL_HANDSHAKE 中的偏移量
#define SSL_HS_EARLY_SESSION_OFFSET 664

// s3->client_random 在 ssl3_state_st 中的偏移量
#define SSL_S3_CLIENT_RANDOM_OFFSET 48



/////////////////////////////////////////// DON'T REMOVE THIS CODE BLOCK. //////////////////////////////////////////

// SSL_MAX_MD_SIZE is size of the largest hash function used in TLS, SHA-384.
#define SSL_MAX_MD_SIZE 48

//  memory layout, see README.md for more detail.
// ssl_st->s3->hs
// bssl::SSL_HANDSHAKE->secret_
#define SSL_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*0

// bssl::SSL_HANDSHAKE->early_traffic_secret_
#define SSL_HANDSHAKE_EARLY_TRAFFIC_SECRET_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*1

// bssl::SSL_HANDSHAKE->client_handshake_secret_
#define SSL_HANDSHAKE_CLIENT_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*2

// bssl::SSL_HANDSHAKE->server_handshake_secret_
#define SSL_HANDSHAKE_SERVER_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*3

// bssl::SSL_HANDSHAKE->client_traffic_secret_0_
#define SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*4

// bssl::SSL_HANDSHAKE->server_traffic_secret_0_
#define SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*5

// bssl::SSL_HANDSHAKE->expected_client_finished_
#define SSL_HANDSHAKE_EXPECTED_CLIENT_FINISHED_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*6
///////////////////////////  END   ///////////////////////////

#endif

#include "openssl.h"
#include "boringssl_masterkey.h"
