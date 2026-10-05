#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail(const char *message) {
  fprintf(stderr, "%s\n", message);
  return 1;
}

int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: %s HOST PORT PATH TOKEN tls12|tls13\n", argv[0]);
    return 2;
  }

  const char *host = argv[1];
  const int port = atoi(argv[2]);
  const char *path = argv[3];
  const char *token = argv[4];
  const char *tls_version = argv[5];

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == NULL)
    return fail("SSL_CTX_new failed");
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  if (strcmp(tls_version, "tls12") == 0) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
  } else if (strcmp(tls_version, "tls13") == 0) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  } else {
    SSL_CTX_free(ctx);
    return fail("unknown TLS version");
  }

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    SSL_CTX_free(ctx);
    return fail("socket failed");
  }
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_port = htons((uint16_t)port)};
  if (inet_pton(AF_INET, host, &address.sin_addr) != 1 ||
      connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    close(fd);
    SSL_CTX_free(ctx);
    return fail("connect failed");
  }

  SSL *ssl = SSL_new(ctx);
  if (ssl == NULL)
    return fail("SSL_new failed");
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, "localhost");
  if (SSL_connect(ssl) != 1)
    return fail("SSL_connect failed");

  char request[1024];
  const int request_len = snprintf(
      request, sizeof(request),
      "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
  if (request_len <= 0 || request_len >= (int)sizeof(request) ||
      SSL_write(ssl, request, request_len) <= 0)
    return fail("SSL_write failed");

  char response[4096];
  char full_response[16384];
  size_t response_size = 0;
  int read_len;
  while ((read_len = SSL_read(ssl, response, sizeof(response) - 1)) > 0) {
    response[read_len] = '\0';
    fwrite(response, 1, (size_t)read_len, stdout);
    if (response_size + (size_t)read_len < sizeof(full_response)) {
      memcpy(full_response + response_size, response, (size_t)read_len);
      response_size += (size_t)read_len;
    }
  }
  full_response[response_size] = '\0';
  const bool found = strstr(full_response, token) != NULL;

  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(fd);
  SSL_CTX_free(ctx);
  return found ? 0 : fail("response token not found");
}
