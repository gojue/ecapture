// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#pragma once

/////////////////////////////////////////// DON'T REMOVE THIS CODE BLOCK. //////////////////////////////////////////
// SSL_MAX_MD_SIZE is size of the largest hash function used in TLS, SHA-384.
#define SSL_MAX_MD_SIZE 48

#ifdef BORINGSSL_INPLACEVECTOR_SECRETS
//
// Android 16+ layout: TLS 1.3 secret fields use InplaceVector<uint8_t, 48>.
// InplaceVector has 48 bytes of data storage (at offset 0) followed by a
// uint8_t size_ field at offset 48, totalling 49 bytes per field.
// There is no separate hash_len_ field; the length is stored in each
// InplaceVector's size_ member.
//
// The offsets (BSSL__SSL_HANDSHAKE_SECRET, etc.) are defined directly in the
// per-version kern header (e.g. boringssl_a_16_kern.c) via offsetof().
//

// hash_len: read from secret.size_ (defined as BSSL__SSL_HANDSHAKE_HASH_LEN in kern header)
#define SSL_HANDSHAKE_HASH_LEN_ BSSL__SSL_HANDSHAKE_HASH_LEN

#define SSL_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_SECRET
#define SSL_HANDSHAKE_EARLY_TRAFFIC_SECRET_ BSSL__SSL_HANDSHAKE_EARLY_TRAFFIC_SECRET
#define SSL_HANDSHAKE_CLIENT_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_CLIENT_HANDSHAKE_SECRET
#define SSL_HANDSHAKE_SERVER_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_SERVER_HANDSHAKE_SECRET
#define SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_ BSSL__SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0
#define SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_ BSSL__SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0
#define SSL_HANDSHAKE_EXPECTED_CLIENT_FINISHED_ BSSL__SSL_HANDSHAKE_EXPECTED_CLIENT_FINISHED

#else
//
// Android 15 and earlier layout: TLS 1.3 secret fields are raw arrays.
//
// memory layout from boringssl repo  ssl/internal.h line 1720
// struct of struct SSL_HANDSHAKE
/*
  // via boringssl source code  src/ssl/internal.h : line 1585

  // max_version is the maximum accepted protocol version, taking account both
  // |SSL_OP_NO_*| and |SSL_CTX_set_max_proto_version| APIs.
  uint16_t max_version = 0;

 private:
  size_t hash_len_ = 0;
  uint8_t secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t early_traffic_secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t client_handshake_secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t server_handshake_secret_[SSL_MAX_MD_SIZE] = {0};
  uint8_t client_traffic_secret_0_[SSL_MAX_MD_SIZE] = {0};
  uint8_t server_traffic_secret_0_[SSL_MAX_MD_SIZE] = {0};
  uint8_t expected_client_finished_[SSL_MAX_MD_SIZE] = {0};
  */
// In BoringSSL, TLS 1.3 keys are private fields, so direct offsetof
// calculation is not possible.  Compute the offset by finding the address
// of the field preceding the private section (max_version at offset 30),
// then the first private field (size_t hash_len_) sits at offset 32 after
// alignment. secret_ is at 32 + sizeof(size_t) = 40, and subsequent
// fields are at SSL_MAX_MD_SIZE increments.


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

#endif /* BORINGSSL_INPLACEVECTOR_SECRETS */

///////////////////////////  END   ///////////////////////////
