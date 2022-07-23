#include "ecapture.h"


// https://wiki.openssl.org/index.php/TLS1.3
// 仅openssl 1.1.1 后才支持 TLS 1.3 协议

// openssl 1.1.1.X 版本相关的常量
#define SSL3_RANDOM_SIZE 32
#define MASTER_SECRET_MAX_LEN 48
#define EVP_MAX_MD_SIZE 64

/*
 * openssl 1.1.1.X 版本相关的常量
 * 参考：https://wiki.openssl.org/index.php/TLS1.3
 */

////////// TLS 1.2 or older /////////
// ssl->session 在 ssl_st 结构中的偏移量
#define SSL_SESSION_OFFSET 0x510

// session->ssl_session_st 在 SSL_SESSION 中的偏移量
#define MASTER_KEY_OFFSET 80

// ssl->s3 在 ssl_st中的偏移量
#define SSL_S3_OFFSET 0xA8

// s3->client_random 在 ssl3_state_st 中的偏移量
#define SSL_S3_CLIENT_RANDOM_OFFSET 0xD8




////////// TLS 1.3 /////////

/*
     // openssl 1.1.1J repo: https://github.com/openssl/openssl/tree/OpenSSL_1_1_1j
     // ssl/ssl_local.h line 1143
     * The TLS1.3 secrets.
    unsigned char early_secret[EVP_MAX_MD_SIZE];
    unsigned char handshake_secret[EVP_MAX_MD_SIZE];  // 【NEED】
    unsigned char master_secret[EVP_MAX_MD_SIZE]; // 【NEED】
    unsigned char resumption_master_secret[EVP_MAX_MD_SIZE];
    unsigned char client_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_hash[EVP_MAX_MD_SIZE]; //【NEED】
    unsigned char handshake_traffic_hash[EVP_MAX_MD_SIZE]; //【NEED】
    unsigned char client_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char server_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char exporter_master_secret[EVP_MAX_MD_SIZE];  //【NEED】
    unsigned char early_exporter_master_secret[EVP_MAX_MD_SIZE];
*/

// session->cipher 在 SSL_SESSION 中的偏移量
#define CIPHER_OFFSET 0xEC

// ssl_cipher_st-> id 在 ssl_cipher_st 中的偏移量
#define CIPHER_ID_OFFSET 0x18

// ssl->handshake_secret 在 ssl_st 中的偏移量
#define HANDSHAKE_SECRET_OFFSET 0x13C // 316

// ssl->master_secret 在 ssl_st 中的偏移量
#define MASTER_SECRET_OFFSET 0x17C        //380

// ssl->server_finished_hash 在 ssl_st 中的偏移量
#define SERVER_FINISHED_HASH_OFFSET 0x27C // 636

// ssl->handshake_traffic_hash 在 ssl_st 中的偏移量
#define HANDSHAKE_TRAFFIC_HASH_OFFSET 0x2BC // 700

// ssl->exporter_master_secret 在 ssl_st 中的偏移量
#define EXPORTER_MASTER_SECRET_OFFSET 0x37C // 892


struct mastersecret_t {
    // TLS 1.2 or older
    s32 version;
    u8 client_random[SSL3_RANDOM_SIZE];
    u8 master_key[MASTER_SECRET_MAX_LEN];

    // TLS 1.3
    u32 cipher_id;
    u8 handshake_secret[EVP_MAX_MD_SIZE];
    u8 master_secret[EVP_MAX_MD_SIZE];
    u8 server_finished_hash[EVP_MAX_MD_SIZE];
    u8 handshake_traffic_hash[EVP_MAX_MD_SIZE];
    u8 exporter_master_secret[EVP_MAX_MD_SIZE];
};

// ssl/ssl_local.h 1556行
struct ssl3_state_st {
    long flags;
    size_t read_mac_secret_size;
    unsigned char read_mac_secret[EVP_MAX_MD_SIZE];
    size_t write_mac_secret_size;
    unsigned char write_mac_secret[EVP_MAX_MD_SIZE];
    unsigned char server_random[SSL3_RANDOM_SIZE];
    unsigned char client_random[SSL3_RANDOM_SIZE];
};

#define TLS1_3_VERSION  0x0304

/////////////////////////BPF MAPS ////////////////////////////////

// bpf map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} mastersecret_events SEC(".maps");

struct {
       __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, u64);
        __type(value, struct mastersecret_t);
        __uint(max_entries, 2048);
} bpf_context SEC(".maps");

struct {
       __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, u32);
        __type(value, struct mastersecret_t);
        __uint(max_entries, 1);
} bpf_context_gen SEC(".maps");

/////////////////////////COMMON FUNCTIONS ////////////////////////////////
//这个函数用来规避512字节栈空间限制，通过在堆上创建内存的方式，避开限制
static __always_inline struct mastersecret_t *make_event() {
    u32 key_gen = 0;
    struct mastersecret_t *bpf_ctx = bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
    if (!bpf_ctx)
        return 0;
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bpf_context, &id, bpf_ctx, BPF_ANY);
    return bpf_map_lookup_elem(&bpf_context, &id);
}


/////////////////////////BPF FUNCTIONS ////////////////////////////////
SEC("uprobe/SSL_write_key")
int probe_ssl_master_key(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid >> 32;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid) {
        return 0;
    }
#endif
    debug_bpf_printk("openssl uprobe/SSL_write masterKey PID :%d\n", pid);

    // mastersecret_t sent to userspace
    struct mastersecret_t *mastersecret = make_event();
    // Get a ssl_st pointer
    void *ssl_st_ptr = (void *)PT_REGS_PARM1(ctx);
    if (!mastersecret) {
        debug_bpf_printk("mastersecret is null\n");
        return 0;
    }
    // Get a ssl_session_st pointer
    u64 *ssl_session_st_ptr = (u64 *)(ssl_st_ptr + SSL_SESSION_OFFSET);
    u64 *ssl_s3_st_ptr = (u64 *)(ssl_st_ptr + SSL_S3_OFFSET);

    int version;
    int ret = bpf_probe_read_user(&version, sizeof(version), (void *)ssl_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read tls_version failed, ret :%d\n", ret);
        return 0;
    }
    debug_bpf_printk("tls_version: %d\n", version);

    u64 address;
    ret =
        bpf_probe_read_user(&address, sizeof(address), ssl_session_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl_session_st_ptr failed, ret :%d\n", ret);
        return 0;
    }

    // Access the TLS 1.2 master secret
    void *ms_ptr = (void *)(address + MASTER_KEY_OFFSET);
    ret = bpf_probe_read_user(&mastersecret->master_key,
                              sizeof(mastersecret->master_key), ms_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read MASTER_KEY_OFFSET failed, ret :%d\n", ret);
        return 0;
    }

    debug_bpf_printk("master_key: %x %x %x\n",mastersecret->master_key[0],mastersecret->master_key[1],mastersecret->master_key[2]);


    // Get ssl3_state_st pointer
    ret = bpf_probe_read_user(&address, sizeof(address), ssl_s3_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl_s3_st_ptr pointer failed, ret :%d\n", ret);
        return 0;
    }

    struct ssl3_state_st ssl3_stat;
    ret = bpf_probe_read_user(&ssl3_stat, sizeof(ssl3_stat), (void *)address);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl3_state_st struct failed, ret :%d\n", ret);
        return 0;
    }
    debug_bpf_printk("client_random: %x %x %x\n",ssl3_stat.client_random[0],ssl3_stat.client_random[1],ssl3_stat.client_random[2]);
    ret = bpf_probe_read_kernel(&mastersecret->client_random,
                        sizeof(mastersecret->client_random),
                        (void *)&ssl3_stat.client_random);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read_kernel ssl3_stat.client_random failed, ret :%d\n", ret);
        return 0;
    }

    bpf_perf_event_output(ctx, &mastersecret_events, BPF_F_CURRENT_CPU, mastersecret,
                        sizeof(struct mastersecret_t));

    // check tls version eq to TLS 1.3
    if (version != TLS1_3_VERSION) {
        return 0;
    }
    // TLS 1.3 master secret
    void *ms_ptr_tls13 = (void *)(ssl_st_ptr + MASTER_SECRET_OFFSET);
    unsigned char master_secret[EVP_MAX_MD_SIZE];
    ret = bpf_probe_read_user(&master_secret, sizeof(master_secret), (void *)ms_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read MASTER_SECRET_OFFSET failed, ret :%d\n", ret);
        return 0;
    }
    debug_bpf_printk("*****master_secret*****: %x %x %x\n",master_secret[0],master_secret[1],master_secret[2]);
    return 0;
}