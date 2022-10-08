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
#ifdef BORINGSSL
//------------------------------------------
// android boringssl 版本
// ssl->version 在 ssl_st 结构体中的偏移量
#define SSL_VERSION_OFFSET 16

// ssl->session 在 ssl_st 结构中的偏移量
#define SSL_SESSION_OFFSET 88

// session->secret 在 SSL_SESSION 中的偏移量
#define MASTER_KEY_OFFSET 16

// ssl->s3 在 ssl_st中的偏移量
#define SSL_S3_OFFSET 48

// s3->hs 在 ssl3_state_st 中的偏移量
#define SSL_HS_OFFSET 272

// hs->established_session 在 SSL_HANDSHAKE 中的偏移量
#define SSL_ESTABLISHED_SESSION_OFFSET 456

// hs->new_session 在 SSL_HANDSHAKE 中的偏移量
#define SSL_HS_NEW_SESSION_OFFSET 656

// hs->early_session 在 SSL_HANDSHAKE 中的偏移量
#define SSL_HS_EARLY_SESSION_OFFSET 664

// s3->client_random 在 ssl3_state_st 中的偏移量
#define SSL_S3_CLIENT_RANDOM_OFFSET 48
//------------------------------------------
#else
// ssl->version 在 ssl_st 结构体中的偏移量
#define SSL_VERSION_OFFSET 0
// ssl->session 在 ssl_st 结构中的偏移量
#define SSL_SESSION_OFFSET 0x510

// session->master_key 在 SSL_SESSION 中的偏移量
#define MASTER_KEY_OFFSET 80

// ssl->s3 在 ssl_st中的偏移量
#define SSL_S3_OFFSET 0xA8

// s3->client_random 在 ssl3_state_st 中的偏移量
#define SSL_S3_CLIENT_RANDOM_OFFSET 0xD8
#endif

////////// TLS 1.2 or older /////////

// session->cipher 在 SSL_SESSION 中的偏移量
#define SESSION_CIPHER_OFFSET 496

// session->cipher_id 在 SSL_SESSION 中的偏移量
#define SESSION_CIPHER_ID_OFFSET 0x1f8

// cipher->id 在 ssl_cipher_st 中的偏移量
#define CIPHER_ID_OFFSET 0x18

////////// TLS 1.3 /////////

/*
     // openssl 1.1.1J repo:
   https://github.com/openssl/openssl/tree/OpenSSL_1_1_1j
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

// ssl->handshake_secret 在 ssl_st 中的偏移量
#define HANDSHAKE_SECRET_OFFSET 0x17C  // 380

// ssl->master_secret 在 ssl_st 中的偏移量
#define MASTER_SECRET_OFFSET 0x1BC  // 444

// ssl->server_finished_hash 在 ssl_st 中的偏移量
#define SERVER_FINISHED_HASH_OFFSET 0x2BC  // 700

// ssl->handshake_traffic_hash 在 ssl_st 中的偏移量
#define HANDSHAKE_TRAFFIC_HASH_OFFSET 0x2FC  // 764

// ssl->exporter_master_secret 在 ssl_st 中的偏移量
#define EXPORTER_MASTER_SECRET_OFFSET 0x3BC  // 956

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
#ifdef BORINGSSL
    //  确保BORINGSSL的state_st 中client_random 的偏移量是48
    u64 unused;
#else
    size_t read_mac_secret_size;
    unsigned char read_mac_secret[EVP_MAX_MD_SIZE];
    size_t write_mac_secret_size;
    unsigned char write_mac_secret[EVP_MAX_MD_SIZE];
#endif
    unsigned char server_random[SSL3_RANDOM_SIZE];
    unsigned char client_random[SSL3_RANDOM_SIZE];
};

#define TLS1_1_VERSION 0x0302
#define TLS1_2_VERSION 0x0303
#define TLS1_3_VERSION 0x0304

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
    struct mastersecret_t *bpf_ctx =
        bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
    if (!bpf_ctx) return 0;
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bpf_context, &id, bpf_ctx, BPF_ANY);
    return bpf_map_lookup_elem(&bpf_context, &id);
}

#ifdef BORINGSSL
// in boringssl, the master secret is stored in src/ssl/ssl_session.cc
// SSL_SESSION *SSL_get_session(const SSL *ssl)
static __always_inline u64 get_session_addr(void *ssl_st_ptr, u64 s3_address) {
    u64 tmp_address;
    //  zero: 优先获取  s3->established_session
    u64 *ssl_established_session_ptr =
        (u64 *)(s3_address + SSL_ESTABLISHED_SESSION_OFFSET);
    int ret = bpf_probe_read_user(&tmp_address, sizeof(tmp_address),
                                  ssl_established_session_ptr);
    if (ret == 0 && tmp_address != 0) {
        return tmp_address;
    }

    // get hs pointer
    u64 *ssl_hs_st_ptr = (u64 *)(s3_address + SSL_HS_OFFSET);
    ret = bpf_probe_read_user(&tmp_address, sizeof(tmp_address), ssl_hs_st_ptr);
    if (ret) {
        debug_bpf_printk("bpf_probe_read ssl_hs_st_ptr failed, ret :%d\n", ret);
        return 0;
    }
    debug_bpf_printk("ssl_hs_st_ptr :%llx\n", ssl_hs_st_ptr);

    // first: ssl_st->s3->hs->early_session
    u64 *ssl_early_session_st_ptr =
        (u64 *)(ssl_hs_st_ptr + SSL_HS_EARLY_SESSION_OFFSET);
    ret = bpf_probe_read_user(&tmp_address, sizeof(tmp_address),
                              ssl_early_session_st_ptr);
    if (ret == 0 && tmp_address != 0) {
        debug_bpf_printk(
            "ssl_st->s3->hs->early_session is not null, address :%llx",
            tmp_address);
        return tmp_address;
    }

    // second: ssl_st->s3->hs->new_session
    u64 *ssl_new_session_st_ptr =
        (u64 *)(ssl_hs_st_ptr + SSL_HS_NEW_SESSION_OFFSET);
    ret = bpf_probe_read_user(&tmp_address, sizeof(tmp_address),
                              ssl_new_session_st_ptr);
    // if ret !=0 or tmp_address == 0 then we try to get the session from
    // ssl_st
    if (ret == 0 && tmp_address != 0) {
        debug_bpf_printk(
            "ssl_st->s3->hs->new_session is not null, address :%llx",
            tmp_address);
        return tmp_address;
    }

    // third: ssl_st->session
    u64 *ssl_session_st_ptr = (u64 *)(ssl_st_ptr + SSL_SESSION_OFFSET);
    ret = bpf_probe_read_user(&tmp_address, sizeof(tmp_address),
                              ssl_session_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_st_ptr:%llx, "
            "ssl_session_st_ptr:%llx  failed, ret :%d\n",
            ssl_st_ptr, ssl_new_session_st_ptr, ret);
        return 0;
    }
    debug_bpf_printk("ssl_st:%llx, ssl_st->session is not null, address :%llx",
                     ssl_st_ptr, tmp_address);
    return tmp_address;
}
#endif

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
    u64 *ssl_version_ptr = (u64 *)(ssl_st_ptr + SSL_VERSION_OFFSET);
    // Get a ssl_session_st pointer
    u64 *ssl_s3_st_ptr = (u64 *)(ssl_st_ptr + SSL_S3_OFFSET);

    // Get SSL->version pointer
    int version;
    u64 address;
    u64 s3_address;
    int ret =
        bpf_probe_read_user(&version, sizeof(version), (void *)ssl_version_ptr);
    if (ret) {
        debug_bpf_printk("bpf_probe_read tls_version failed, ret :%d\n", ret);
        return 0;
    }
#ifdef BORINGSSL
    mastersecret->version = version & 0xFFFF;  //  uint16_t version;
#else
    mastersecret->version = version;  // int version;
#endif
    debug_bpf_printk("TLS version :%d\n", mastersecret->version);

    // Get ssl3_state_st pointer
    ret = bpf_probe_read_user(&address, sizeof(address), ssl_s3_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl_s3_st_ptr pointer failed, ret :%d\n", ret);
        return 0;
    }
    s3_address = address;
    struct ssl3_state_st ssl3_stat;
    ret = bpf_probe_read_user(&ssl3_stat, sizeof(ssl3_stat), (void *)address);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl3_state_st struct failed, ret :%d\n", ret);
        return 0;
    }
    debug_bpf_printk("client_random: %x %x %x\n", ssl3_stat.client_random[0],
                     ssl3_stat.client_random[1], ssl3_stat.client_random[2]);
    ret = bpf_probe_read_kernel(&mastersecret->client_random,
                                sizeof(mastersecret->client_random),
                                (void *)&ssl3_stat.client_random);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read_kernel ssl3_stat.client_random failed, ret :%d\n",
            ret);
        return 0;
    }

    // Get ssl_session_st pointer
    u64 *ssl_session_st_ptr;
    u64 ssl_session_st_addr;
#ifdef BORINGSSL
    ssl_session_st_addr = get_session_addr(ssl_st_ptr, s3_address);
    if (ssl_session_st_addr == 0) {
        debug_bpf_printk("ssl_session_st_addr is null\n");
        return 0;
    }

#else
    ssl_session_st_ptr = (u64 *)(ssl_st_ptr + SSL_SESSION_OFFSET);
    ret = bpf_probe_read_user(&ssl_session_st_addr, sizeof(ssl_session_st_addr),
                              ssl_session_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_session_st_ptr failed, ret :%d\n",
            ret);
        return 0;
    }
#endif
    ///////////////////////// get TLS 1.2 master secret ////////////////////
    if (mastersecret->version != TLS1_3_VERSION) {
        void *ms_ptr = (void *)(ssl_session_st_addr + MASTER_KEY_OFFSET);
        ret = bpf_probe_read_user(&mastersecret->master_key,
                                  sizeof(mastersecret->master_key), ms_ptr);
        if (ret) {
            debug_bpf_printk(
                "bpf_probe_read MASTER_KEY_OFFSET failed, ms_ptr:%llx, ret "
                ":%d\n",
                ms_ptr, ret);
            return 0;
        }

        debug_bpf_printk("master_key: %x %x %x\n", mastersecret->master_key[0],
                         mastersecret->master_key[1],
                         mastersecret->master_key[2]);

        bpf_perf_event_output(ctx, &mastersecret_events, BPF_F_CURRENT_CPU,
                              mastersecret, sizeof(struct mastersecret_t));
        return 0;
    }

    ///////////////////////// get TLS 1.3 master secret ////////////////////
    // Get SSL_SESSION->cipher pointer
    u64 *ssl_cipher_st_ptr =
        (u64 *)(ssl_session_st_addr + SESSION_CIPHER_OFFSET);

    // get cipher_suite_st pointer
    debug_bpf_printk("cipher_suite_st pointer: %x\n", ssl_cipher_st_ptr);
    ret = bpf_probe_read_user(&address, sizeof(address), ssl_cipher_st_ptr);
    if (ret || address == 0) {
        debug_bpf_printk(
            "bpf_probe_read ssl_cipher_st_ptr failed, ret :%d, address:%x\n",
            ret, address);
        // return 0;
        void *cipher_id_ptr =
            (void *)(ssl_session_st_addr + SESSION_CIPHER_ID_OFFSET);
        ret =
            bpf_probe_read_user(&mastersecret->cipher_id,
                                sizeof(mastersecret->cipher_id), cipher_id_ptr);
        if (ret) {
            debug_bpf_printk(
                "bpf_probe_read SESSION_CIPHER_ID_OFFSET failed from "
                "SSL_SESSION->cipher_id, ret :%d\n",
                ret);
            return 0;
        }
    } else {
        debug_bpf_printk("cipher_suite_st value: %x\n", address);
        void *cipher_id_ptr = (void *)(address + CIPHER_ID_OFFSET);
        ret =
            bpf_probe_read_user(&mastersecret->cipher_id,
                                sizeof(mastersecret->cipher_id), cipher_id_ptr);
        if (ret) {
            debug_bpf_printk(
                "bpf_probe_read CIPHER_ID_OFFSET failed from "
                "ssl_cipher_st->id, ret :%d\n",
                ret);
            return 0;
        }
    }

    debug_bpf_printk("cipher_id: %d\n", mastersecret->cipher_id);

    //////////////////// TLS 1.3 master secret ////////////////////////

    void *hs_ptr_tls13 = (void *)(ssl_st_ptr + HANDSHAKE_SECRET_OFFSET);
    ret = bpf_probe_read_user(&mastersecret->handshake_secret,
                              sizeof(mastersecret->handshake_secret),
                              (void *)hs_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read HANDSHAKE_SECRET_OFFSET failed, ret :%d\n", ret);
        return 0;
    }

    void *ms_ptr_tls13 = (void *)(ssl_st_ptr + MASTER_SECRET_OFFSET);
    ret = bpf_probe_read_user(&mastersecret->master_secret,
                              sizeof(mastersecret->master_secret),
                              (void *)ms_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read MASTER_SECRET_OFFSET failed, ret :%d\n", ret);
        return 0;
    }

    void *sf_ptr_tls13 = (void *)(ssl_st_ptr + SERVER_FINISHED_HASH_OFFSET);
    ret = bpf_probe_read_user(&mastersecret->server_finished_hash,
                              sizeof(mastersecret->server_finished_hash),
                              (void *)sf_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SERVER_FINISHED_HASH_OFFSET failed, ret :%d\n",
            ret);
        return 0;
    }

    void *hth_ptr_tls13 = (void *)(ssl_st_ptr + HANDSHAKE_TRAFFIC_HASH_OFFSET);
    ret = bpf_probe_read_user(&mastersecret->handshake_traffic_hash,
                              sizeof(mastersecret->handshake_traffic_hash),
                              (void *)hth_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read HANDSHAKE_TRAFFIC_HASH_OFFSET failed, ret :%d\n",
            ret);
        return 0;
    }

    void *ems_ptr_tls13 = (void *)(ssl_st_ptr + EXPORTER_MASTER_SECRET_OFFSET);
    ret = bpf_probe_read_user(&mastersecret->exporter_master_secret,
                              sizeof(mastersecret->exporter_master_secret),
                              (void *)ems_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read EXPORTER_MASTER_SECRET_OFFSET failed, ret :%d\n",
            ret);
        return 0;
    }
    debug_bpf_printk(
        "*****master_secret*****: %x %x %x\n", mastersecret->master_secret[0],
        mastersecret->master_secret[1], mastersecret->master_secret[2]);
    bpf_perf_event_output(ctx, &mastersecret_events, BPF_F_CURRENT_CPU,
                          mastersecret, sizeof(struct mastersecret_t));
    return 0;
}