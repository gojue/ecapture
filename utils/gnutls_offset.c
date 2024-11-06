// bootstrap
// configure
// clang -I gnulib/lib/ -I lib/ -I . gnutls_offset.c -o offset

#include <stddef.h>
#include <stdio.h>
#include <config.h>
#include <lib/gnutls_int.h>

#define SSL_STRUCT_OFFSETS                                      \
    X(gnutls_session_int, security_parameters)                  \
    X(gnutls_session_int, security_parameters.prf)              \
    X(mac_entry_st, id)                                         \
    X(gnutls_session_int, security_parameters.client_random)    \
    X(gnutls_session_int, security_parameters.master_secret)    \
    X(gnutls_session_int, key.proto.tls13.hs_ckey)              \
    X(gnutls_session_int, key.proto.tls13.hs_skey)              \
    X(gnutls_session_int, key.proto.tls13.ap_ckey)              \
    X(gnutls_session_int, key.proto.tls13.ap_skey)              \
    X(gnutls_session_int, key.proto.tls13.ap_expkey)

#define SSL_ANY_STRUCT_OFFSETS                                  \
    Y(security_parameters_st, pversion)                         \
    Y(version_entry_st, id)

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

#define X(struct_name, field_name) format(#struct_name, #field_name, offsetof(struct struct_name, field_name));
    SSL_STRUCT_OFFSETS
#undef X

#define Y(struct_name, field_name) format(#struct_name, #field_name, offsetof(struct_name, field_name));
    SSL_ANY_STRUCT_OFFSETS
#undef Y

    return 0;
}
