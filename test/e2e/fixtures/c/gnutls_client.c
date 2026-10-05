#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail(const char *message, int code) {
  if (code < 0)
    fprintf(stderr, "%s: %s\n", message, gnutls_strerror(code));
  else
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
  const char *priority;
  if (strcmp(tls_version, "tls12") == 0) {
    priority = "NORMAL:-VERS-ALL:+VERS-TLS1.2";
  } else if (strcmp(tls_version, "tls13") == 0) {
    priority = "NORMAL:-VERS-ALL:+VERS-TLS1.3";
  } else {
    return fail("unknown TLS version", 0);
  }

  gnutls_certificate_credentials_t credentials;
  gnutls_session_t session;
  int result = gnutls_global_init();
  if (result < 0)
    return fail("gnutls_global_init failed", result);
  result = gnutls_certificate_allocate_credentials(&credentials);
  if (result < 0)
    return fail("allocate credentials failed", result);
  result = gnutls_init(&session, GNUTLS_CLIENT);
  if (result < 0)
    return fail("gnutls_init failed", result);
  result = gnutls_priority_set_direct(session, priority, NULL);
  if (result < 0)
    return fail("set priority failed", result);
  result = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);
  if (result < 0)
    return fail("set credentials failed", result);
  result = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost",
                                  strlen("localhost"));
  if (result < 0)
    return fail("set server name failed", result);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return fail("socket failed", 0);
  struct sockaddr_in address = {.sin_family = AF_INET,
                                .sin_port = htons((uint16_t)port)};
  if (inet_pton(AF_INET, host, &address.sin_addr) != 1 ||
      connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0)
    return fail("connect failed", 0);
  gnutls_transport_set_int(session, fd);

  do {
    result = gnutls_handshake(session);
  } while (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED);
  if (result < 0)
    return fail("TLS handshake failed", result);

  char request[1024];
  const int request_len = snprintf(
      request, sizeof(request),
      "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
  result = (int)gnutls_record_send(session, request, (size_t)request_len);
  if (result < 0)
    return fail("gnutls_record_send failed", result);

  char response[4096];
  char full_response[16384];
  size_t response_size = 0;
  do {
    result = (int)gnutls_record_recv(session, response, sizeof(response) - 1);
    if (result > 0) {
      response[result] = '\0';
      fwrite(response, 1, (size_t)result, stdout);
      if (response_size + (size_t)result < sizeof(full_response)) {
        memcpy(full_response + response_size, response, (size_t)result);
        response_size += (size_t)result;
      }
    }
  } while (result > 0 || result == GNUTLS_E_AGAIN ||
           result == GNUTLS_E_INTERRUPTED);
  full_response[response_size] = '\0';
  const bool found = strstr(full_response, token) != NULL;

  gnutls_bye(session, GNUTLS_SHUT_RDWR);
  close(fd);
  gnutls_deinit(session);
  gnutls_certificate_free_credentials(credentials);
  gnutls_global_deinit();
  return found ? 0 : fail("response token not found", 0);
}
