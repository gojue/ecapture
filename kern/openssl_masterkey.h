// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ecapture.h"

// https://wiki.openssl.org/index.php/TLS1.3
// 仅openssl 1.1.1 后才支持 TLS 1.3 协议

// openssl 1.1.1.X 版本相关的常量
#define SSL3_RANDOM_SIZE 32
#define MASTER_SECRET_MAX_LEN 48
#define EVP_MAX_MD_SIZE 64

struct mastersecret_t {
    // TLS 1.2 or older
    s32 version;
    u8 client_random[SSL3_RANDOM_SIZE];
    u8 master_key[MASTER_SECRET_MAX_LEN];

    // TLS 1.3
    u32 cipher_id;
    u8 handshake_secret[EVP_MAX_MD_SIZE];
    u8 handshake_traffic_hash[EVP_MAX_MD_SIZE];
    u8 client_app_traffic_secret[EVP_MAX_MD_SIZE];
    u8 server_app_traffic_secret[EVP_MAX_MD_SIZE];
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
// 这个函数用来规避512字节栈空间限制，通过在堆上创建内存的方式，避开限制
static __always_inline struct mastersecret_t *make_event() {
    u32 key_gen = 0;
    struct mastersecret_t *bpf_ctx =
        bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
    if (!bpf_ctx) return 0;
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
    u32 uid = current_uid_gid;

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
    u64 *ssl_version_ptr = (u64 *)(ssl_st_ptr + SSL_ST_VERSION);
    // Get a ssl_session_st pointer
    u64 *ssl_s3_st_ptr = (u64 *)(ssl_st_ptr + SSL_ST_S3);

    // Get SSL->version pointer
    int version;
    u64 address;
    int ret =
        bpf_probe_read_user(&version, sizeof(version), (void *)ssl_version_ptr);
    if (ret) {
        debug_bpf_printk("bpf_probe_read tls_version failed, ret :%d\n", ret);
        return 0;
    }
    mastersecret->version = version;  // int version;
    debug_bpf_printk("TLS version :%d\n", mastersecret->version);

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

    ssl_session_st_ptr = (u64 *)(ssl_st_ptr + SSL_ST_SESSION);
    ret = bpf_probe_read_user(&ssl_session_st_addr, sizeof(ssl_session_st_addr),
                              ssl_session_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_session_st_ptr failed, ret :%d\n",
            ret);
        return 0;
    }

    ///////////////////////// get TLS 1.2 master secret ////////////////////
    if (mastersecret->version != TLS1_3_VERSION) {
        void *ms_ptr =
            (void *)(ssl_session_st_addr + SSL_SESSION_ST_MASTER_KEY);
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
        (u64 *)(ssl_session_st_addr + SSL_SESSION_ST_CIPHER);

    // get cipher_suite_st pointer
    debug_bpf_printk("cipher_suite_st pointer: %x\n", ssl_cipher_st_ptr);
    ret = bpf_probe_read_user(&address, sizeof(address), ssl_cipher_st_ptr);
    if (ret || address == 0) {
        debug_bpf_printk(
            "bpf_probe_read ssl_cipher_st_ptr failed, ret :%d, address:%x\n",
            ret, address);
        // return 0;
        void *cipher_id_ptr =
            (void *)(ssl_session_st_addr + SSL_SESSION_ST_CIPHER_ID);
        ret =
            bpf_probe_read_user(&mastersecret->cipher_id,
                                sizeof(mastersecret->cipher_id), cipher_id_ptr);
        if (ret) {
            debug_bpf_printk(
                "bpf_probe_read SSL_SESSION_ST_CIPHER_ID failed from "
                "SSL_SESSION->cipher_id, ret :%d\n",
                ret);
            return 0;
        }
    } else {
        debug_bpf_printk("cipher_suite_st value: %x\n", address);
        void *cipher_id_ptr = (void *)(address + SSL_CIPHER_ST_ID);
        ret =
            bpf_probe_read_user(&mastersecret->cipher_id,
                                sizeof(mastersecret->cipher_id), cipher_id_ptr);
        if (ret) {
            debug_bpf_printk(
                "bpf_probe_read SSL_CIPHER_ST_ID failed from "
                "ssl_cipher_st->id, ret :%d\n",
                ret);
            return 0;
        }
    }

    debug_bpf_printk("cipher_id: %d\n", mastersecret->cipher_id);

    //////////////////// TLS 1.3 master secret ////////////////////////

    void *hs_ptr_tls13 = (void *)(ssl_st_ptr + SSL_ST_HANDSHAKE_SECRET);
    ret = bpf_probe_read_user(&mastersecret->handshake_secret,
                              sizeof(mastersecret->handshake_secret),
                              (void *)hs_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_ST_HANDSHAKE_SECRET failed, ret :%d\n", ret);
        return 0;
    }

    void *hth_ptr_tls13 = (void *)(ssl_st_ptr + SSL_ST_HANDSHAKE_TRAFFIC_HASH);
    ret = bpf_probe_read_user(&mastersecret->handshake_traffic_hash,
                              sizeof(mastersecret->handshake_traffic_hash),
                              (void *)hth_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_ST_HANDSHAKE_TRAFFIC_HASH failed, ret :%d\n",
            ret);
        return 0;
    }

    void *cats_ptr_tls13 =
        (void *)(ssl_st_ptr + SSL_ST_CLIENT_APP_TRAFFIC_SECRET);
    ret = bpf_probe_read_user(&mastersecret->client_app_traffic_secret,
                              sizeof(mastersecret->client_app_traffic_secret),
                              (void *)cats_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_ST_CLIENT_APP_TRAFFIC_SECRET failed, ret :%d\n",
            ret);
        return 0;
    }

    void *sats_ptr_tls13 =
        (void *)(ssl_st_ptr + SSL_ST_SERVER_APP_TRAFFIC_SECRET);
    ret = bpf_probe_read_user(&mastersecret->server_app_traffic_secret,
                              sizeof(mastersecret->server_app_traffic_secret),
                              (void *)sats_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_ST_SERVER_APP_TRAFFIC_SECRET failed, ret :%d\n",
            ret);
        return 0;
    }

    void *ems_ptr_tls13 = (void *)(ssl_st_ptr + SSL_ST_EXPORTER_MASTER_SECRET);
    ret = bpf_probe_read_user(&mastersecret->exporter_master_secret,
                              sizeof(mastersecret->exporter_master_secret),
                              (void *)ems_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_ST_EXPORTER_MASTER_SECRET failed, ret :%d\n",
            ret);
        return 0;
    }
    debug_bpf_printk("*****master_secret*****: %x %x %x\n",
                     mastersecret->master_key[0], mastersecret->master_key[1],
                     mastersecret->master_key[2]);
    bpf_perf_event_output(ctx, &mastersecret_events, BPF_F_CURRENT_CPU,
                          mastersecret, sizeof(struct mastersecret_t));
    return 0;
}
