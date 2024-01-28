#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER "127.0.0.1"
#define PORT 443
#define REQUEST "GET / HTTP/1.1\r\nHost: www.cnxct.com\r\n\r\n"
//#define TEST_CNT 10000000
#define TEST_CNT 1

char g_requests[TEST_CNT][strlen(REQUEST) + 1];
int create_socket(const char *host, int port) {
    int sockfd;
    struct sockaddr_in dest_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(host);

    memset(&(dest_addr.sin_zero), '\0', 8);

    if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

void init_request() {
    int i;
    for (i = 0; i < TEST_CNT; i++) {
        memcpy(g_requests[i], REQUEST, strlen(REQUEST));
    }

}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    char reply[4096];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    server = create_socket(SERVER, PORT);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);
    SSL_connect(ssl);

    init_request();
    int request_len = strlen(REQUEST);

    // Perform SSL_write performance test
    int i;
    for (i = 0; i < TEST_CNT; i++) {
        char *request = g_requests[i];
        int bytes_written = SSL_write(ssl, request, request_len);  // Perform SSL_write
        if (bytes_written <= 0) {
            fprintf(stderr, "SSL_write failed\n");
            ERR_print_errors_fp(stderr);
            break;
        }
    }

    int bytes_read = SSL_read(ssl, reply, sizeof(reply));  // Read server response
    fprintf(stderr, "received %d bytes",bytes_read);

    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}