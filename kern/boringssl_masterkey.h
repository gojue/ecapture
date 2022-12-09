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
// 仅openssl/boringssl 1.1.1 后才支持 TLS 1.3 协议

// boringssl 1.1.1 版本相关的常量
#define SSL3_RANDOM_SIZE 32
#define MASTER_SECRET_MAX_LEN 48
#define EVP_MAX_MD_SIZE 64

struct mastersecret_bssl_t {
    // TLS 1.2 or older
    s32 version;
    u8 client_random[SSL3_RANDOM_SIZE];
    u8 secret_[MASTER_SECRET_MAX_LEN];

    // TLS 1.3
    u32 cipher_id;

    // ????
    u8 early_traffic_secret_[EVP_MAX_MD_SIZE];
    u8 client_handshake_secret_[EVP_MAX_MD_SIZE];
    u8 server_handshake_secret_[EVP_MAX_MD_SIZE];

    // SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_
    u8 client_traffic_secret_0_[EVP_MAX_MD_SIZE];


    u8 server_traffic_secret_0_[EVP_MAX_MD_SIZE];
    u8 exporter_secret[EVP_MAX_MD_SIZE];
};

// ssl/internal.h line 2653   SSL3_STATE
struct ssl3_state_st {
    u64 read_sequence;
    //  确保BORINGSSL的state_st 中client_random 的偏移量是48
    u64 write_sequence;
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
    __type(value, struct mastersecret_bssl_t);
    __uint(max_entries, 2048);
} bpf_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct mastersecret_bssl_t);
    __uint(max_entries, 1);
} bpf_context_gen SEC(".maps");

/////////////////////////COMMON FUNCTIONS ////////////////////////////////
// 这个函数用来规避512字节栈空间限制，通过在堆上创建内存的方式，避开限制
static __always_inline struct mastersecret_bssl_t *make_event() {
    u32 key_gen = 0;
    struct mastersecret_bssl_t *bpf_ctx =
        bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
    if (!bpf_ctx) return 0;
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bpf_context, &id, bpf_ctx, BPF_ANY);
    return bpf_map_lookup_elem(&bpf_context, &id);
}

// in boringssl, the master secret is stored in src/ssl/ssl_session.cc
// SSL_SESSION *SSL_get_session(const SSL *ssl)
// ssl_handshake_session
static __always_inline u64 get_session_addr(void *ssl_st_ptr, u64 s3_address) {
    u64 tmp_address;
    int ret;
    //  zero: 优先获取  s3->established_session
    u64 *ssl_established_session_ptr =
        (u64 *)(s3_address + BSSL__SSL3_STATE_ESTABLISHED_SESSION);
    ret = bpf_probe_read_user(&tmp_address, sizeof(tmp_address),
                              ssl_established_session_ptr);
    if (ret == 0 && tmp_address != 0) {
        return tmp_address;
    }
    // get hs pointer
    u64 *ssl_hs_st_ptr = (u64 *)(s3_address + BSSL__SSL3_STATE_HS);
    ret = bpf_probe_read_user(&tmp_address, sizeof(tmp_address), ssl_hs_st_ptr);
    if (ret) {
        debug_bpf_printk("bpf_probe_read ssl_hs_st_ptr failed, ret :%d\n", ret);
        return 0;
    }
    debug_bpf_printk("ssl_hs_st_ptr :%llx\n", ssl_hs_st_ptr);

    // first: ssl_st->s3->hs->early_session
    u64 *ssl_early_session_st_ptr =
        (u64 *)(ssl_hs_st_ptr + BSSL__SSL_HANDSHAKE_EARLY_SESSION);
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
        (u64 *)(ssl_hs_st_ptr + BSSL__SSL_HANDSHAKE_NEW_SESSION);
    ret = bpf_probe_read_user(&tmp_address, sizeof(tmp_address),
                              ssl_new_session_st_ptr);
    // if ret !=0 or tmp_address == 0 then we try to get the session from
    // ssl_st
    if (ret == 0 && tmp_address != 0) {
        debug_bpf_printk(
            "ssl_st->s3->hs->new_session is not null, address :%llx\n",
            tmp_address);
        return tmp_address;
    }

    // third: ssl_st->session
    u64 *ssl_session_st_ptr = (u64 *)(ssl_st_ptr + SSL_ST_SESSION);
    ret = bpf_probe_read_user(&tmp_address, sizeof(tmp_address),
                              ssl_session_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_st_ptr:%llx, "
            "ssl_session_st_ptr:%llx  failed, ret :%d\n",
            ssl_st_ptr, ssl_new_session_st_ptr, ret);
        return 0;
    }
    debug_bpf_printk(
        "ssl_st:%llx, ssl_st->session is not null, address :%llx\n", ssl_st_ptr,
        tmp_address);
    return tmp_address;
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

    // mastersecret_bssl_t sent to userspace
    struct mastersecret_bssl_t *mastersecret = make_event();
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
    u64 s3_address;
    int ret =
        bpf_probe_read_user(&version, sizeof(version), (void *)ssl_version_ptr);
    if (ret) {
        debug_bpf_printk("bpf_probe_read tls_version failed, ret :%d\n", ret);
        return 0;
    }
    mastersecret->version = version & 0xFFFF;  //  uint16_t version;
    debug_bpf_printk("TLS version :%d\n", mastersecret->version);

    // Get ssl3_state_st pointer
    ret = bpf_probe_read_user(&address, sizeof(address), ssl_s3_st_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl_s3_st_ptr pointer failed, ret :%d\n", ret);
        return 0;
    }
    s3_address = address;
    debug_bpf_printk("s3_address :%llx\n", s3_address);

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

    ///////////////////////// get TLS 1.2 master secret ////////////////////
    if (mastersecret->version != TLS1_3_VERSION) {
        // Get ssl_session_st pointer
//        u64 *ssl_session_st_ptr;
        u64 ssl_session_st_addr;
        ssl_session_st_addr = get_session_addr(ssl_st_ptr, s3_address);
        if (ssl_session_st_addr == 0) {
            debug_bpf_printk("ssl_session_st_addr is null\n");
            return 0;
        }
        debug_bpf_printk("s3_address:%llx, ssl_session_st_addr addr :%llx\n",
                         s3_address, ssl_session_st_addr);

        s32 secret_length;
        u64 *ms_len_ptr = (u64 *)(ssl_session_st_addr + SSL_SESSION_ST_SECRET_LENGTH);
        ret = bpf_probe_read_user(&secret_length,
                                  sizeof(secret_length), ms_len_ptr);
        if (ret) {
            debug_bpf_printk(
                    "bpf_probe_read SSL_SESSION_ST_SECRET_LENGTH failed, ms_len_ptr:%llx, ret "
                    ":%d\n",
                    ms_len_ptr, ret);
                return 0;
        }
        debug_bpf_printk(" secret_length:%d\n",secret_length);

        u64 *ms_ptr = (u64 *)(ssl_session_st_addr + SSL_SESSION_ST_SECRET);
        ret = bpf_probe_read_user(&mastersecret->secret_,
                                  sizeof(mastersecret->secret_), ms_ptr);
        if (ret) {
            debug_bpf_printk(
                "bpf_probe_read SSL_SESSION_ST_SECRET failed, ms_ptr:%llx, ret "
                ":%d\n",
                ms_ptr, ret);
            return 0;
        }

        debug_bpf_printk("master_key: %x %x %x\n", mastersecret->secret_[0],
                         mastersecret->secret_[1], mastersecret->secret_[2]);

        bpf_perf_event_output(ctx, &mastersecret_events, BPF_F_CURRENT_CPU,
                              mastersecret, sizeof(struct mastersecret_bssl_t));
        return 0;
    }

    // get s3->hs address first
    u64 ssl_hs_st_addr;
    u64 *ssl_hs_st_ptr = (u64 *)(s3_address + BSSL__SSL3_STATE_HS);
    ret = bpf_probe_read_user(&ssl_hs_st_addr, sizeof(ssl_hs_st_addr),
                              ssl_hs_st_ptr);
    if (ret) {
        debug_bpf_printk("bpf_probe_read ssl_hs_st_ptr failed, ret :%d\n", ret);
        return 0;
    }

    void *hs_ptr_tls13 =
        (void *)(ssl_hs_st_addr + SSL_HANDSHAKE_CLIENT_HANDSHAKE_SECRET_);
    ret = bpf_probe_read_user(&mastersecret->client_handshake_secret_,
                              sizeof(mastersecret->client_handshake_secret_),
                              (void *)hs_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_HANDSHAKE_CLIENT_HANDSHAKE_SECRET_ failed, ret "
            ":%d\n",
            ret);
        return 0;
    }

    //////////////////// TLS 1.3 master secret ////////////////////////

    void *hth_ptr_tls13 =
        (void *)(ssl_hs_st_addr + SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_);
    ret = bpf_probe_read_user(&mastersecret->server_handshake_secret_,
                              sizeof(mastersecret->server_handshake_secret_),
                              (void *)hth_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_ failed, ret "
            ":%d\n",
            ret);
        return 0;
    }

    void *cats_ptr_tls13 =
        (void *)(ssl_hs_st_addr + SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_);
    ret = bpf_probe_read_user(&mastersecret->client_traffic_secret_0_,
                              sizeof(mastersecret->client_traffic_secret_0_),
                              (void *)cats_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_HANDSHAKE_CLIENT_TRAFFIC_SECRET_0_ failed, ret "
            ":%d\n",
            ret);
        return 0;
    }

    void *sats_ptr_tls13 =
        (void *)(ssl_hs_st_addr + SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_);
    ret = bpf_probe_read_user(&mastersecret->server_traffic_secret_0_,
                              sizeof(mastersecret->server_traffic_secret_0_),
                              (void *)sats_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_HANDSHAKE_SERVER_TRAFFIC_SECRET_0_ failed, ret "
            ":%d\n",
            ret);
        return 0;
    }

    void *ems_ptr_tls13 =
        (void *)(ssl_hs_st_addr + SSL_HANDSHAKE_EXPECTED_CLIENT_FINISHED_);
    ret = bpf_probe_read_user(&mastersecret->exporter_secret,
                              sizeof(mastersecret->exporter_secret),
                              (void *)ems_ptr_tls13);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read SSL_HANDSHAKE_EXPECTED_CLIENT_FINISHED_ failed, "
            "ret :%d\n",
            ret);
        return 0;
    }
    debug_bpf_printk("*****master_secret*****: %x %x %x\n",
                     mastersecret->secret_[0], mastersecret->secret_[1],
                     mastersecret->secret_[2]);
    bpf_perf_event_output(ctx, &mastersecret_events, BPF_F_CURRENT_CPU,
                          mastersecret, sizeof(struct mastersecret_bssl_t));
    return 0;
}