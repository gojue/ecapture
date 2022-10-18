// clang -I include/ -I . offset.c -o off

#include <stdio.h>
#include <stddef.h>
#include <ssl/ssl_local.h>
#include <openssl/crypto.h>

#define SSL_STRUCT_OFFSETS               \
    X(ssl_st, version)              \
    X(ssl_st, session)              \
    X(ssl_st, s3)              \
    X(ssl_session_st, master_key)        \
    X(ssl3_state_st, client_random)      \
    X(ssl_session_st, cipher) \
    X(ssl_session_st, cipher_id) \
    X(ssl_cipher_st, id) \
    X(ssl_st, handshake_secret)          \
    X(ssl_st, master_secret)             \
    X(ssl_st, server_finished_hash)    \
    X(ssl_st, handshake_traffic_hash)    \
    X(ssl_st, exporter_master_secret)

int main() {
    printf("/* OPENSSL_VERSION_TEXT: %s, OPENSSL_VERSION_NUMBER:%ld */\n",
           OPENSSL_VERSION_TEXT, OPENSSL_VERSION_NUMBER);

#define X(struct_name, field_name)                         \
    printf("// "#struct_name"->"#field_name" \n#define " #struct_name "_" #field_name " 0x%lx\n", \
           offsetof(struct struct_name, field_name));
    SSL_STRUCT_OFFSETS
#undef X
    return 0;
}