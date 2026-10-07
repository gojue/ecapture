#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

static int64_t monotonic_microseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s HOST PORT TOKEN PAYLOAD_BYTES tls12|tls13\n", argv[0]);
        return 2;
    }

    const char *host = argv[1];
    const int port = atoi(argv[2]);
    const char *token = argv[3];
    const long payload_bytes = strtol(argv[4], NULL, 10);
    const char *tls_version = argv[5];
    if (port <= 0 || port > 65535 || payload_bytes <= 0) {
        return fail("invalid port or payload size");
    }

    signal(SIGPIPE, SIG_IGN);
    const int64_t started_us = monotonic_microseconds();
    if (started_us < 0) {
        return fail("clock_gettime failed");
    }

    int result = 1;
    int fd = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *request = NULL;
    char response[65536];
    size_t response_size = 0;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        fail("SSL_CTX_new failed");
        goto cleanup;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (strcmp(tls_version, "tls12") == 0) {
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    } else if (strcmp(tls_version, "tls13") == 0) {
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    } else {
        fail("unknown TLS version");
        goto cleanup;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fail("socket failed");
        goto cleanup;
    }
    struct timeval timeout = {.tv_sec = 15, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
    };
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fail("connect failed");
        goto cleanup;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL || SSL_set_fd(ssl, fd) != 1 || SSL_set_tlsext_host_name(ssl, "localhost") != 1 ||
        SSL_connect(ssl) != 1) {
        fail("TLS connection failed");
        goto cleanup;
    }

    const size_t header_capacity = strlen(token) + 512;
    char *header = malloc(header_capacity);
    if (header == NULL) {
        fail("header allocation failed");
        goto cleanup;
    }
    const int header_len = snprintf(header, header_capacity,
        "POST /upload HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %ld\r\n"
        "X-Ecapture-Benchmark: %s\r\n\r\n",
        payload_bytes, token);
    if (header_len <= 0 || (size_t)header_len >= header_capacity) {
        free(header);
        fail("request header is too large");
        goto cleanup;
    }

    const size_t request_len = (size_t)header_len + (size_t)payload_bytes;
    request = malloc(request_len);
    if (request == NULL) {
        free(header);
        fail("request allocation failed");
        goto cleanup;
    }
    memcpy(request, header, (size_t)header_len);
    memset(request + header_len, 'x', (size_t)payload_bytes);
    free(header);

    size_t written = 0;
    while (written < request_len) {
        const size_t remaining = request_len - written;
        const int chunk = remaining > INT32_MAX ? INT32_MAX : (int)remaining;
        const int n = SSL_write(ssl, request + written, chunk);
        if (n <= 0) {
            fail("SSL_write failed");
            goto cleanup;
        }
        written += (size_t)n;
    }

    while (response_size + 1 < sizeof(response)) {
        const int n = SSL_read(ssl, response + response_size, (int)(sizeof(response) - response_size - 1));
        if (n <= 0) {
            break;
        }
        response_size += (size_t)n;
    }
    response[response_size] = '\0';

    const char *direction = strstr(token, "_REQ_");
    if (direction == NULL) {
        fail("request token has no direction marker");
        goto cleanup;
    }
    const size_t token_prefix_len = (size_t)(direction - token);
    const char *token_suffix = direction + strlen("_REQ_");
    const size_t response_token_size = strlen(token) + 2;
    char *response_token = malloc(response_token_size);
    if (response_token == NULL) {
        fail("response token allocation failed");
        goto cleanup;
    }
    (void)snprintf(response_token, response_token_size, "%.*s_RESP_%s", (int)token_prefix_len, token, token_suffix);
    if (strstr(response, "HTTP/1.1 200") == NULL || strstr(response, response_token) == NULL) {
        free(response_token);
        fail("benchmark response validation failed");
        goto cleanup;
    }
    free(response_token);

    const int64_t finished_us = monotonic_microseconds();
    if (finished_us < started_us) {
        fail("invalid monotonic duration");
        goto cleanup;
    }
    printf("%lld\n", (long long)(finished_us - started_us));
    result = 0;

cleanup:
    free(request);
    if (ssl != NULL) {
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (fd >= 0) {
        close(fd);
    }
    SSL_CTX_free(ctx);
    return result;
}
