#ifndef ECAPTURE_BORINGSSL_CONST_H
#define ECAPTURE_BORINGSSL_CONST_H

/////////////////////////////////////////// DON'T REMOVE THIS CODE BLOCK. //////////////////////////////////////////

// memory layout from boringssl repo  ssl/internal.h line 1720
// struct of struct SSL_HANDSHAKE

// SSL_MAX_MD_SIZE is size of the largest hash function used in TLS, SHA-384.
#define SSL_MAX_MD_SIZE 48

// ssl_st->s3->hs
// bssl::SSL_HANDSHAKE->secret_
#define SSL_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*0

// bssl::SSL_HANDSHAKE->early_traffic_secret_
#define SSL_HANDSHAKE_EARLY_TRAFFIC_SECRET_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*1

// bssl::SSL_HANDSHAKE->client_handshake_secret_
#define SSL_HANDSHAKE_CLIENT_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*2

// bssl::SSL_HANDSHAKE->server_handshake_secret_
#define SSL_HANDSHAKE_SERVER_HANDSHAKE_SECRET_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*3

// bssl::SSL_HANDSHAKE->client_traffic_secret_0_
#define SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*4

// bssl::SSL_HANDSHAKE->server_traffic_secret_0_
#define SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*5

// bssl::SSL_HANDSHAKE->expected_client_finished_
#define SSL_HANDSHAKE_EXPECTED_CLIENT_FINISHED_ BSSL__SSL_HANDSHAKE_MAX_VERSION+8+SSL_MAX_MD_SIZE*6

///////////////////////////  END   ///////////////////////////

#endif