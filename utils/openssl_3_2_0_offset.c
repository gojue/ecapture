// clang -I include/ -I . offset.c -o offset
#include <crypto/bio/bio_local.h>
#include <openssl/crypto.h>
#include <ssl/ssl_local.h>
#include <stddef.h>
#include <stdio.h>

#define SSL_STRUCT_OFFSETS                          \
    X(ssl_st, type)                                 \
    X(ssl_connection_st, version)                   \
    X(ssl_connection_st, session)                   \
    X(ssl_connection_st, s3)                        \
    X(ssl_connection_st, rbio)                      \
    X(ssl_connection_st, wbio)                      \
    X(ssl_connection_st, server)                    \
    X(ssl_session_st, master_key)                   \
    X(ssl_connection_st, s3.client_random)          \
    X(ssl_session_st, cipher)                       \
    X(ssl_session_st, cipher_id)                    \
    X(ssl_cipher_st, id)                            \
    X(ssl_connection_st, handshake_secret)          \
    X(ssl_connection_st, handshake_traffic_hash)    \
    X(ssl_connection_st, client_app_traffic_secret) \
    X(ssl_connection_st, server_app_traffic_secret) \
    X(ssl_connection_st, exporter_master_secret)    \
    X(bio_st, num)                                  \
    X(quic_conn_st, tls)

void toUpper(char *s) {
    int i = 0;
    while (s[i] != '\0') {
        if (s[i] == '.') {
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
    printf("/* OPENSSL_VERSION_NUMBER: %ld */\n\n", OPENSSL_VERSION_NUMBER);
#define X(struct_name, field_name) \
    format(#struct_name, #field_name, offsetof(struct struct_name, field_name));
    SSL_STRUCT_OFFSETS
#undef X

    return 0;
}
