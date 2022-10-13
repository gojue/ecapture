//  g++ -I include/ -I src/ ./src/offset.c -o off
#include <stdio.h>
#include <stddef.h>
#include <ssl/internal.h>
#include <openssl/base.h>
#include <openssl/crypto.h>

#define SSL_STRUCT_OFFSETS               \
    X(ssl_st, version)              \
    X(ssl_st, session)              \
    X(ssl_st, s3)              \
    X(ssl_session_st, secret)        \
    X(ssl_session_st, secret_length)  \
    X(bssl::SSL3_STATE, hs) \
    X(bssl::SSL3_STATE, client_random)      \
    X(ssl_session_st, cipher) \
    X(ssl_session_st, cipher_id) \
    X(ssl_cipher_st, id) \
    X(ssl_st, handshake_secret)          \
    X(ssl_st, master_secret)             \
    X(bssl::SSL_HANDSHAKE, server_finished_secret)    \
    X(bssl::SSL_HANDSHAKE, handshake_traffic_hash)    \
    X(bssl::SSL_HANDSHAKE, exporter_master_secret)


int main() {
    printf("/* OPENSSL_VERSION_TEXT: %s, OPENSSL_VERSION_NUMBER:%ld */\n",
           OPENSSL_VERSION_TEXT, OPENSSL_VERSION_NUMBER);

#define X(struct_name, field_name)                         \
    printf("#define " #struct_name "_" #field_name " 0x%lx\n", \
           offsetof(struct struct_name, field_name));
    SSL_STRUCT_OFFSETS
#undef X
    return 0;
}