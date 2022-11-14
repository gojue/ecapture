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

/*
  size_t hash_len_ = 0;
  uint8_t secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t early_traffic_secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t client_handshake_secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t server_handshake_secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t client_traffic_secret_0_[SSL_MAX_MD_SIZE] = {0};
  uint8_t server_traffic_secret_0_[SSL_MAX_MD_SIZE] = {0};
  uint8_t expected_client_finished_[SSL_MAX_MD_SIZE] = {0};
  */
// bssl::SSL_HANDSHAKE_max_version = 30

///////////////////////////  NEW   ///////////////////////////
// bssl::SSL_HANDSHAKE->secret_
#define SSL_HANDSHAKE_SECRET_ = 40

// bssl::SSL_HANDSHAKE->early_traffic_secret_
#define SSL_HANDSHAKE_EARLY_TRAFFIC_SECRET_ = 88

// bssl::SSL_HANDSHAKE->client_handshake_secret_
#define SSL_HANDSHAKE_CLIENT_HANDSHAKE_SECRET_ = 136

// bssl::SSL_HANDSHAKE->server_handshake_secret_
#define SSL_HANDSHAKE_SERVER_HANDSHAKE_SECRET_ = 184

// bssl::SSL_HANDSHAKE->client_traffic_secret_0_
#define SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_ = 232

// bssl::SSL_HANDSHAKE->server_traffic_secret_0_
#define SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_ = 280

// bssl::SSL_HANDSHAKE->expected_client_finished_
#define SSL_HANDSHAKE_EXPECTED_CLIENT_FINISHED_ = 328
///////////////////////////  END   ///////////////////////////

// ssl->handshake_secret 在 ssl_st 中的偏移量
#define SSL_ST_HANDSHAKE_SECRET 0x17c  // 380

// ssl->handshake_traffic_hash 在 ssl_st 中的偏移量
#define SSL_ST_HANDSHAKE_TRAFFIC_HASH 0x2fc  // 764

// ssl_st->client_app_traffic_secret
#define SSL_ST_CLIENT_APP_TRAFFIC_SECRET 0x33c  // 828

// ssl_st->server_app_traffic_secret
#define SSL_ST_SERVER_APP_TRAFFIC_SECRET 0x37c  // 892

// ssl->exporter_master_secret 在 ssl_st 中的偏移量
#define SSL_ST_EXPORTER_MASTER_SECRET 0x3bc  // 956

#endif

#include "openssl.h"
#include "boringssl_masterkey.h"
