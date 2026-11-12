// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Real loopback DTLS traffic. Secrets are collected only by eCapture.
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void require(int ok, const char *operation) {
    if (!ok) {
        fprintf(stderr, "DTLS fixture failed: %s\n", operation);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}

struct endpoint {
    SSL_CTX *context;
    int fd, server;
    struct sockaddr_in address, remote;
    const char *token, *cipher;
};

static void open_endpoint(struct endpoint *endpoint, const char *cert, const char *key) {
    endpoint->context = SSL_CTX_new(DTLS_method());
    require(endpoint->context != NULL, "SSL_CTX_new");
    require(SSL_CTX_set_min_proto_version(endpoint->context, DTLS1_2_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(endpoint->context, DTLS1_2_VERSION) == 1,
        "DTLS version");
    require(SSL_CTX_set_cipher_list(endpoint->context, endpoint->cipher) == 1, "cipher selection");
    SSL_CTX_set_options(endpoint->context, SSL_OP_NO_QUERY_MTU);
    if (endpoint->server) {
        require(SSL_CTX_use_certificate_file(endpoint->context, cert, SSL_FILETYPE_PEM) == 1 &&
                    SSL_CTX_use_PrivateKey_file(endpoint->context, key, SSL_FILETYPE_PEM) == 1 &&
                    SSL_CTX_check_private_key(endpoint->context) == 1,
            "certificate");
    } else {
        SSL_CTX_set_verify(endpoint->context, SSL_VERIFY_NONE, NULL);
    }
    endpoint->fd = socket(AF_INET, SOCK_DGRAM, 0);
    require(endpoint->fd >= 0, "socket");
    endpoint->address.sin_family = AF_INET;
    endpoint->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(bind(endpoint->fd, (struct sockaddr *)&endpoint->address, sizeof(endpoint->address)) == 0, "bind");
    socklen_t size = sizeof(endpoint->address);
    require(getsockname(endpoint->fd, (struct sockaddr *)&endpoint->address, &size) == 0, "getsockname");
    struct timeval timeout = {.tv_sec = 5};
    require(setsockopt(endpoint->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "receive timeout");
}

static void exchange(SSL *ssl, const char *token, int server, int index, int outgoing) {
    unsigned char payload[256] = {0, 255}, received[256];
    const char *sender = (server == outgoing) ? "SERVER" : "CLIENT";
    int count = snprintf((char *)payload + 2, sizeof(payload) - 2, "%s_%s_%d\n", token, sender, index);
    require(count > 0 && count < (int)sizeof(payload) - 2, "payload length");
    count += 2;
    if (outgoing) {
        require(SSL_write(ssl, payload, count) == count, "application write");
    } else {
        int actual = SSL_read(ssl, received, sizeof(received));
        require(actual == count && memcmp(received, payload, (size_t)count) == 0, "exact binary application read");
    }
}

static void *serve_endpoint(void *arg) {
    struct endpoint *endpoint = arg;
    SSL *ssl = SSL_new(endpoint->context);
    require(ssl != NULL, "SSL_new");
    BIO *bio = BIO_new_dgram(endpoint->fd, BIO_NOCLOSE);
    require(bio != NULL, "BIO_new_dgram");
    require(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &endpoint->remote) != 0, "connected BIO");
    SSL_set_bio(ssl, bio, bio);
    require(SSL_set_mtu(ssl, 512) != 0, "MTU");
    require((endpoint->server ? SSL_accept(ssl) : SSL_connect(ssl)) == 1, "handshake");
    require(SSL_version(ssl) == DTLS1_2_VERSION && strcmp(SSL_get_cipher_name(ssl), endpoint->cipher) == 0,
        "negotiated version and cipher");
    for (int index = 0; index < 4; index++) {
        exchange(ssl, endpoint->token, endpoint->server, index, !endpoint->server);
        exchange(ssl, endpoint->token, endpoint->server, index, endpoint->server);
    }
    int shutdown = SSL_shutdown(ssl);
    require(shutdown >= 0 && (shutdown == 1 || SSL_shutdown(ssl) == 1), "shutdown");
    // A reusable SSL may retain its session while SSL_clear resets client_random.
    // These ordinary hook calls must not publish an uninitialized secret event.
    require(SSL_clear(ssl) == 1, "clear completed connection");
    unsigned char random[SSL3_RANDOM_SIZE], zero[SSL3_RANDOM_SIZE] = {0};
    require(SSL_get_session(ssl) != NULL && SSL_get_client_random(ssl, random, sizeof(random)) == sizeof(random) &&
                memcmp(random, zero, sizeof(random)) == 0,
        "retained session with reset client random");
    require(SSL_in_before(ssl) == 1, "reset handshake state");
    (void)SSL_get_wbio(ssl);
    printf("DTLS1.2 cipher=%s server=%d sent=4 received=4 reset=1\n", endpoint->cipher, endpoint->server);
    SSL_free(ssl);
    require(close(endpoint->fd) == 0, "close");
    SSL_CTX_free(endpoint->context);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s CERT KEY TOKEN aes128|aes256\n", argv[0]);
        return 2;
    }
    require(strcmp(argv[4], "aes128") == 0 || strcmp(argv[4], "aes256") == 0, "suite");
    const char *cipher = strcmp(argv[4], "aes128") == 0 ? "ECDHE-RSA-AES128-GCM-SHA256" : "ECDHE-RSA-AES256-GCM-SHA384";
    struct endpoint peers[2] = {
        {.token = argv[3], .cipher = cipher}, {.token = argv[3], .cipher = cipher, .server = 1}};
    for (int index = 0; index < 2; index++) open_endpoint(&peers[index], argv[1], argv[2]);
    for (int index = 0; index < 2; index++) {
        peers[index].remote = peers[1 - index].address;
        require(connect(peers[index].fd, (struct sockaddr *)&peers[index].remote, sizeof(peers[index].remote)) == 0,
            "connect");
    }
    pthread_t server;
    require(pthread_create(&server, NULL, serve_endpoint, &peers[1]) == 0, "pthread_create");
    serve_endpoint(&peers[0]);
    require(pthread_join(server, NULL) == 0, "pthread_join");
    return 0;
}
