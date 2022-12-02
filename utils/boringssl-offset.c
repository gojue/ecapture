// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//  g++ -I include/ -I src/ ./src/offset.c -o off
#include <stdio.h>
#include <stddef.h>
#include <ssl/internal.h>
#include <openssl/base.h>
#include <openssl/crypto.h>

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
// boringssl中的 TLS 1.3 密钥是 private属性，无法直接offset计算。
// 所以，计算private前面的属性地址，再手动相加。
// private 前面的属性是max_version ，offset是30
// private 第一个属性是size_t hash_len_，内存对齐后，offset就是32
// secret的offset即 32 + sizeof(size_t) ，即 40 。其他的累加 SSL_MAX_MD_SIZE长度即可。
#define SSL_STRUCT_OFFSETS                      \
    X(ssl_st, version)                          \
    X(ssl_st, session)                          \
    X(ssl_st, s3)                               \
    X(ssl_session_st, secret)                   \
    X(ssl_session_st, secret_length)            \
    X(ssl_session_st, cipher)            \
    X(ssl_cipher_st, id)            \
    X(bssl::SSL3_STATE, hs)                     \
    X(bssl::SSL3_STATE, client_random)          \
    X(bssl::SSL_HANDSHAKE, new_session)         \
    X(bssl::SSL_HANDSHAKE, early_session)       \
    X(bssl::SSL3_STATE, established_session)    \
    X(bssl::SSL_HANDSHAKE, max_version)

void toUpper(char *s) {
    int i = 0;
    while (s[i] != '\0') {
          if (s[i] == '.' || s[i] == ':') {
            putchar('_');
          } else {
            putchar(toupper(s[i]));
          }
        i++;
    }
}

void format(char *struct_name, char *field_name, size_t offset) {
    printf("// %s->%s\n", struct_name, field_name);
    printf("#define ");
    toUpper(struct_name);
    printf("_");
    toUpper(field_name);
    printf(" 0x%lx\n\n", offset);
}

int main() {
    printf("/* OPENSSL_VERSION_TEXT: %s, OPENSSL_VERSION_NUMBER: %ld */\n\n",
           OPENSSL_VERSION_TEXT, OPENSSL_VERSION_NUMBER);

#define X(struct_name, field_name)      \
    format(#struct_name, #field_name, offsetof(struct struct_name, field_name));
    SSL_STRUCT_OFFSETS
#undef X

    return 0;
}
