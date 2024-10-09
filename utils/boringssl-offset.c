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
#include <ctype.h>
#include <openssl/base.h>
#include <openssl/crypto.h>
#include <ssl/internal.h>
#include <stddef.h>
#include <stdio.h>

#define SSL_STRUCT_OFFSETS                   \
    X(ssl_st, version)                       \
    X(ssl_st, session)                       \
    X(ssl_st, rbio)                          \
    X(ssl_st, wbio)                          \
    X(ssl_st, s3)                            \
    X(ssl_session_st, secret_length)         \
    X(ssl_session_st, secret)                \
    X(ssl_session_st, cipher)                \
    X(bio_st, num)                           \
    X(bio_st, method)                        \
    X(bio_method_st, type)                   \
    X(ssl_cipher_st, id)                     \
    X(bssl::SSL3_STATE, hs)                  \
    X(bssl::SSL3_STATE, client_random)       \
    X(bssl::SSL3_STATE, exporter_secret)     \
    X(bssl::SSL3_STATE, established_session) \
    X(bssl::SSL_HANDSHAKE, new_session)      \
    X(bssl::SSL_HANDSHAKE, early_session)    \
    X(bssl::SSL_HANDSHAKE, hints)            \
    X(bssl::SSL_HANDSHAKE, client_version)   \
    X(bssl::SSL_HANDSHAKE, state)            \
    X(bssl::SSL_HANDSHAKE, tls13_state)      \
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
    printf("/* OPENSSL_VERSION_TEXT: %s */\n", OPENSSL_VERSION_TEXT);
    printf("/* OPENSSL_VERSION_NUMBER: %d */\n\n", OPENSSL_VERSION_NUMBER);

#define X(struct_name, field_name) format(#struct_name, #field_name, offsetof(struct struct_name, field_name));
    SSL_STRUCT_OFFSETS
#undef X

    return 0;
}
