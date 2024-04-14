#ifndef ECAPTURE_BORINGSSL_CONST_H
#define ECAPTURE_BORINGSSL_CONST_H

/////////////////////////////////////////// DON'T REMOVE THIS CODE BLOCK. //////////////////////////////////////////
// SSL_MAX_MD_SIZE is size of the largest hash function used in TLS, SHA-384.
#define SSL_MAX_MD_SIZE 48


// memory layout from boringssl repo  ssl/internal.h line 1720
// struct of struct SSL_HANDSHAKE
/*
  // via boringssl source code  src/ssl/internal.h : line 1585

  // max_version is the maximum accepted protocol version, taking account both
  // |SSL_OP_NO_*| and |SSL_CTX_set_max_proto_version| APIs.
  uint16_t max_version = 0;

 private:
  size_t hash_len_ = 0;x
  uint8_t secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t early_traffic_secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t client_handshake_secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t server_handshake_secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t client_traffic_secret_0_[SSL_MAX_MD_SIZE] = {0};
  uint8_t server_traffic_secret_0_[SSL_MAX_MD_SIZE] = {0};
  uint8_t expected_client_finished_[SSL_MAX_MD_SIZE] = {0};
  */
// boringssl中的 TLS 1.3 密钥是 private属性，无法直接offset计算。
// 所以，计算private前面的属性地址，再手动相加。
// private 前面的属性是max_version ，offset是30
// private 第一个属性是size_t hash_len_，内存对齐后，offset就是32
// secret的offset即 32 + sizeof(size_t) ，即 40 。其他的累加 SSL_MAX_MD_SIZE长度即可。


//   uint16_t max_version = 0;
// sizeof(uint16_t) = 2
#define SSL_HANDSHAKE_HASH_LEN_ roundup(BSSL__SSL_HANDSHAKE_MAX_VERSION+2,8)

// ssl_st->s3->hs
// bssl::SSL_HANDSHAKE->secret_
#define SSL_HANDSHAKE_SECRET_ SSL_HANDSHAKE_HASH_LEN_+8

// bssl::SSL_HANDSHAKE->early_traffic_secret_
#define SSL_HANDSHAKE_EARLY_TRAFFIC_SECRET_ SSL_HANDSHAKE_SECRET_+SSL_MAX_MD_SIZE*1

// bssl::SSL_HANDSHAKE->client_handshake_secret_
#define SSL_HANDSHAKE_CLIENT_HANDSHAKE_SECRET_ SSL_HANDSHAKE_SECRET_+SSL_MAX_MD_SIZE*2

// bssl::SSL_HANDSHAKE->server_handshake_secret_
#define SSL_HANDSHAKE_SERVER_HANDSHAKE_SECRET_ SSL_HANDSHAKE_SECRET_+SSL_MAX_MD_SIZE*3

// bssl::SSL_HANDSHAKE->client_traffic_secret_0_
#define SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_ SSL_HANDSHAKE_SECRET_+SSL_MAX_MD_SIZE*4

// bssl::SSL_HANDSHAKE->server_traffic_secret_0_
#define SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_ SSL_HANDSHAKE_SECRET_+SSL_MAX_MD_SIZE*5

// bssl::SSL_HANDSHAKE->expected_client_finished_
#define SSL_HANDSHAKE_EXPECTED_CLIENT_FINISHED_ SSL_HANDSHAKE_SECRET_+SSL_MAX_MD_SIZE*6

///////////////////////////  END   ///////////////////////////

#endif