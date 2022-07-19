#include "ecapture.h"

// openssl 1.1.1.X 版本相关的常量
#define SSL3_RANDOM_SIZE 32
#define MASTER_SECRET_MAX_LEN 48
#define EVP_MAX_MD_SIZE 64

// openssl 1.1.1.X 版本相关的偏移量
#define SSL_SESSION_OFFSET 0x510
#define MASTER_SECRET_OFFSET 80
#define SSL_S3_OFFSET 0xA8
#define SSL_S3_CLIENT_RANDOM_OFFSET 0xD8

struct masterkey_t {
    u8 client_random[SSL3_RANDOM_SIZE];
    u8 master_key[MASTER_SECRET_MAX_LEN];
};

// bpf map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//    __uint(type, BPF_MAP_TYPE_HASH);
//    __type(key, u32);
//    __type(value, struct masterkey_t);
//    __uint(max_entries, 1024);
} masterkey_events SEC(".maps");

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

    // masterkey_t sent to userspace
    struct masterkey_t masterkey;
    __builtin_memset(&masterkey, 0, sizeof(masterkey));
    // Get a ssl_st pointer
    void *ssl_st_ptr = (void *)PT_REGS_PARM1(ctx);

    // Get a ssl_session_st pointer
    u64 *ssl_session_st_ptr = (u64 *)(ssl_st_ptr + SSL_SESSION_OFFSET);
    u64 *ssl_s3_st_ptr = (u64 *)(ssl_st_ptr + SSL_S3_OFFSET);

    u64 address;
    int ret =
        bpf_probe_read_user(&address, sizeof(address), ssl_session_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl_session_st_ptr failed, ret :%d\n", ret);
        return 0;
    }

    // Access the TLS 1.2 master secret
    void *ms_ptr = (void *)(address + MASTER_SECRET_OFFSET);
    ret = bpf_probe_read_user(&masterkey.master_key,
                              sizeof(masterkey.master_key), ms_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read MASTER_SECRET_OFFSET failed, ret :%d\n", ret);
        return 0;
    }

    debug_bpf_printk("master_key: %x %x %x\n",masterkey.master_key[0],masterkey.master_key[1],masterkey.master_key[2]);


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
    ret = bpf_probe_read_kernel(&masterkey.client_random,
                        sizeof(masterkey.client_random),
                        (void *)&ssl3_stat.client_random);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read_kernel ssl3_stat.client_random failed, ret :%d\n", ret);
        return 0;
    }
    debug_bpf_printk("copy : %x %x %x\n",masterkey.client_random[0],masterkey.client_random[1],masterkey.client_random[2]);

    bpf_perf_event_output(ctx, &masterkey_events, BPF_F_CURRENT_CPU, &masterkey,
                        sizeof(struct masterkey_t));
    return 0;
}