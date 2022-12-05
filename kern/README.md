# application source doc.

## openssl 1.1.*
### version
* define SSL3_VERSION                    0x0300
* define TLS1_VERSION                    0x0301
* define TLS1_1_VERSION                  0x0302
* define TLS1_2_VERSION                  0x0303
* define TLS1_3_VERSION                  0x0304
* define DTLS1_VERSION                   0xFEFF
* define DTLS1_2_VERSION                 0xFEFD
* define DTLS1_BAD_VER                   0x0100

```c
//https://github.com/openssl/openssl/blob/3e8f70c30d84861fcd257a6e280dc49e104eb145/ssl/ssl_local.h#L1068
struct ssl_st {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;
    /* SSLv3 */
    const SSL_METHOD *method;
    /*
     * There are 2 BIO's even though they are normally both the same.  This
     * is so data can be read and written to different handlers
     */
    /* used by SSL_read */
    BIO *rbio;
    /* used by SSL_write */
    BIO *wbio;
    /* used during session-id reuse to concatenate messages */
    BIO *bbio;

    // ...
}

//https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h
struct bio_st {
    const BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
    BIO_callback_fn callback;
    BIO_callback_fn_ex callback_ex;
    char *cb_arg;               /* first argument for the callback */
    int init;
    int shutdown;
    int flags;                  /* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;    /* used by filter BIOs */
    struct bio_st *prev_bio;    /* used by filter BIOs */
    CRYPTO_REF_COUNT references;
    uint64_t num_read;
    uint64_t num_write;
    CRYPTO_EX_DATA ex_data;
    CRYPTO_RWLOCK *lock;
};
```


## openssl  1.0.*
https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/ssl/ssl.h#L1093
```c
struct ssl_st {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;
    /* SSL_ST_CONNECT or SSL_ST_ACCEPT */
    int type;
    /* SSLv3 */
    const SSL_METHOD *method;
    /*
     * There are 2 BIO's even though they are normally both the same.  This
     * is so data can be read and written to different handlers
     */
# ifndef OPENSSL_NO_BIO
    /* used by SSL_read */
    BIO *rbio;
    /* used by SSL_write */
    BIO *wbio;
    /* used during session-id reuse to concatenate messages */
    BIO *bbio;
# else
    /* used by SSL_read */
    char *rbio;
    /* used by SSL_write */
    char *wbio;
    char *bbio;
# endif
    /*
```


https://github.com/openssl/openssl/blob/OpenSSL_1_0_0-stable/crypto/bio/bio.h
```c
struct bio_st {
    BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
    long (*callback) (struct bio_st *, int, const char *, int, long, long);
    char *cb_arg;               /* first argument for the callback */
    int init;
    int shutdown;
    int flags;                  /* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;    /* used by filter BIOs */
    struct bio_st *prev_bio;    /* used by filter BIOs */
    int references;
    unsigned long num_read;
    unsigned long num_write;
    CRYPTO_EX_DATA ex_data;
};
```

## master secrets 

| openssl label name          | openssl struct                  | Label Name                      | boringssl struct              |     |
|-----------------------------|---------------------------------|---------------------------------|-------------------------------|-----|
| MASTER_SECRET_LABEL         | s->session->master_key          | CLIENT_RANDOM                   | session->secret               |     |     
| EXPORTER_SECRET             | s->exporter_master_secret       | EXPORTER_SECRET                 | ssl->s3->exporter_secret      |     |     
| EARLY_EXPORTER_SECRET_LABEL | s->early_exporter_master_secret | EARLY_EXPORTER_SECRET           | -                             |     |     
| SERVER_APPLICATION_LABEL    | s->server_app_traffic_secret    | SERVER_TRAFFIC_SECRET_0         | hs->server_traffic_secret_0() |     |     
| CLIENT_APPLICATION_LABEL    | s->client_app_traffic_secret    | CLIENT_TRAFFIC_SECRET_0         | hs->client_traffic_secret_0() |     |     
| SERVER_HANDSHAKE_LABEL      |                                 | SERVER_HANDSHAKE_TRAFFIC_SECRET | hs->server_handshake_secret() |     |     
| CLIENT_HANDSHAKE_LABEL      |                                 | CLIENT_HANDSHAKE_TRAFFIC_SECRET | hs->client_handshake_secret() |     |     
| CLIENT_EARLY_LABEL          |                                 | CLIENT_EARLY_TRAFFIC_SECRET     | hs->early_traffic_secret()    |     |     

### EARLY_EXPORTER_SECRET_LABEL  EXPORTER_SECRET_LABEL
-

### SERVER_APPLICATION_LABEL
insecret = s->master_secret;
label = server_application_traffic;
labellen = sizeof(server_application_traffic) - 1;
log_label = SERVER_APPLICATION_LABEL;

### CLIENT_APPLICATION_LABEL
insecret = s->master_secret;
label = client_application_traffic;
labellen = sizeof(client_application_traffic) - 1;
log_label = CLIENT_APPLICATION_LABEL;

### SERVER_HANDSHAKE_LABEL
insecret = s->handshake_secret;
finsecret = s->server_finished_secret;
finsecretlen = EVP_MD_size(ssl_handshake_md(s));
label = server_handshake_traffic;
labellen = sizeof(server_handshake_traffic) - 1;
log_label = SERVER_HANDSHAKE_LABEL;

**再计算**
memcpy(s->handshake_traffic_hash, hashval, hashlen);
derive_secret_key_and_iv(s, which & SSL3_CC_WRITE, md, cipher,
insecret, hash, label, labellen, secret, iv,
ciph_ctx)

### SERVER_HANDSHAKE_LABEL
insecret = s->handshake_secret;
finsecret = s->server_finished_secret;
finsecretlen = EVP_MD_size(ssl_handshake_md(s));
label = server_handshake_traffic;
labellen = sizeof(server_handshake_traffic) - 1;
log_label = SERVER_HANDSHAKE_LABEL;

**再计算**
memcpy(s->handshake_traffic_hash, hashval, hashlen);
derive_secret_key_and_iv(s, which & SSL3_CC_WRITE, md, cipher,
insecret, hash, label, labellen, secret, iv,
ciph_ctx)

### CLIENT_HANDSHAKE_LABEL
insecret = s->handshake_secret;
finsecret = s->client_finished_secret;
finsecretlen = EVP_MD_size(ssl_handshake_md(s));
label = client_handshake_traffic;
labellen = sizeof(client_handshake_traffic) - 1;
log_label = CLIENT_HANDSHAKE_LABEL;
hash = s->handshake_traffic_hash;

### CLIENT_EARLY_LABEL
insecret = s->early_secret;
label = client_early_traffic;
labellen = sizeof(client_early_traffic) - 1;
log_label = CLIENT_EARLY_LABEL;