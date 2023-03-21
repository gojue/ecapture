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

// tls13_state is the internal state for the TLS 1.3 handshake.
// values depend on enum client_hs_state_t

// client_hs_state_t state_done  14
#define TLS_CLIENT_STATE_DONE 14

// tls13_server_hs_state_t state13_done  16
#define TLS_1_3_SERVER_STATE_DONE 16

// tls12_server_hs_state_t state12_done
#define TLS_1_2_SERVER_STATE_DONE 21

struct mastersecret_bssl_t {
    // TLS 1.2 or older
    s32 version;
    u8 client_random[SSL3_RANDOM_SIZE];
    u8 secret_[MASTER_SECRET_MAX_LEN];

    // TLS 1.3
    u32 hash_len;

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

struct ssl3_handshake_st {
    // state is the internal state for the TLS 1.2 and below handshake. Its
    // values depend on |do_handshake| but the starting state is always zero.
    s32 state;

    // tls13_state is the internal state for the TLS 1.3 handshake. Its values
    // depend on |do_handshake| but the starting state is always zero.
    s32 tls13_state;
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

// in boringssl, the master secret is stored in src/ssl/handshake.cc  581
// const SSL_SESSION *ssl_handshake_session(const SSL_HANDSHAKE *hs) {
static __always_inline u64 get_session_addr(void *ssl_st_ptr, u64 s3_address,
                                            u64 ssl_hs_st_ptr) {
    u64 tmp_address;
    int ret;

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
    return tmp_address;
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

    ret = bpf_probe_read_kernel(&mastersecret->client_random,
                                sizeof(mastersecret->client_random),
                                (void *)&ssl3_stat.client_random);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read_kernel ssl3_stat.client_random failed, ret :%d\n",
            ret);
        return 0;
    }

    // get s3->hs address first
    u64 ssl_hs_st_addr;
    u64 *ssl_hs_st_ptr = (u64 *)(s3_address + BSSL__SSL3_STATE_HS);
    ret = bpf_probe_read_user(&ssl_hs_st_addr, sizeof(ssl_hs_st_addr),
                              ssl_hs_st_ptr);
    if (ret || ssl_hs_st_addr == 0) {
        //        debug_bpf_printk("bpf_probe_read ssl_hs_st_ptr failed, ret
        //        :%d\n", ret);
        return 0;
    }

    //////////////////// get hash len //////////////////
    u8 hash_len;
    u64 *ssl_hs_hashlen_ptr = (u64 *)(ssl_hs_st_addr + SSL_HANDSHAKE_HASH_LEN_);
    ret = bpf_probe_read_user(&hash_len, sizeof(hash_len), ssl_hs_hashlen_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl_hs_st_ptr failed, ret :%d, hash_len:%d\n", ret,
            hash_len);
        return 0;
    }
    mastersecret->hash_len = hash_len;

    u16 client_version;
    u64 *ssl_hs_cv_ptr =
        (u64 *)(ssl_hs_st_addr + BSSL__SSL_HANDSHAKE_CLIENT_VERSION);
    ret = bpf_probe_read_user(&client_version, sizeof(client_version),
                              ssl_hs_cv_ptr);
    //    if (ret || client_version == 0) {
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl_hs_st_ptr failed, ret :%d, client_version:%d\n",
            ret, hash_len);
        return 0;
    }

    struct ssl3_handshake_st ssl3_hs_state;
    u64 *ssl_hs_state_ptr = (u64 *)(ssl_hs_st_addr + BSSL__SSL_HANDSHAKE_STATE);
    ret = bpf_probe_read_user(&ssl3_hs_state, sizeof(ssl3_hs_state),
                              (void *)ssl_hs_state_ptr);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read ssl_hs_state_ptr struct failed, ret :%d\n", ret);
        return 0;
    }

    // ssl_client_hs_state_t::ssl3_hs_state=5
    // tls13_server_hs_state_t::state13_read_second_client_flight
    //    if (ssl3_hs_state.state == 5 && ssl3_hs_state.tls13_state < 8) {
    //        return 0;
    //    }
    ///////////// debug info  /////////

    debug_bpf_printk("client_version:%d, state:%d, tls13_state:%d\n",
                     client_version, ssl3_hs_state.state,
                     ssl3_hs_state.tls13_state);
    //    debug_bpf_printk("openssl uprobe/SSL_write masterKey PID :%d\n", pid);
    debug_bpf_printk("TLS version :%d, hash_len:%d, \n", mastersecret->version,
                     hash_len);
    // 判断当前tls链接状态
    // handshake->handshake_finalized = hs_st_addr + BSSL__SSL_HANDSHAKE_HINTS +
    s32 all_bool;
    u64 *hs_ptr_ab = (u64 *)(ssl_hs_st_addr + BSSL__SSL_HANDSHAKE_HINTS + 8);
    ret = bpf_probe_read_user(&all_bool, sizeof(all_bool), hs_ptr_ab);
    if (ret) {
        debug_bpf_printk(
            "bpf_probe_read BSSL__SSL_HANDSHAKE_HINTS failed, ret "
            ":%d, ssl_hs_st_ptr:%lx\n",
            ret, ssl_hs_st_addr);
        return 0;
    }
    debug_bpf_printk("SSL_HANDSHAKE_ALLBOOL:%d, ssl_hs_st_addr:%lx\n", all_bool,
                     ssl_hs_st_addr);

    ///////////////////////// get TLS 1.2 master secret ////////////////////
    if (mastersecret->version != TLS1_3_VERSION) {
        // state12_finish_server_handshake
        // state12_done
        if (ssl3_hs_state.state < 20) {
            // not finished yet.
            return 0;
        }
        // Get ssl_session_st pointer
        u64 ssl_session_st_addr;
        ssl_session_st_addr =
            get_session_addr(ssl_st_ptr, s3_address, ssl_hs_st_addr);
        if (ssl_session_st_addr == 0) {
            //            debug_bpf_printk("ssl_session_st_addr is null\n");
            return 0;
        }
        debug_bpf_printk("s3_address:%llx, ssl_session_st_addr addr :%llx\n",
                         s3_address, ssl_session_st_addr);

        s32 secret_length;
        u64 *ms_len_ptr =
            (u64 *)(ssl_session_st_addr + SSL_SESSION_ST_SECRET_LENGTH);
        ret = bpf_probe_read_user(&secret_length, sizeof(secret_length),
                                  ms_len_ptr);
        if (ret) {
            debug_bpf_printk(
                "bpf_probe_read SSL_SESSION_ST_SECRET_LENGTH failed, "
                "ms_len_ptr:%llx, ret "
                ":%d\n",
                ms_len_ptr, ret);
            return 0;
        }
        mastersecret->hash_len = secret_length;
        debug_bpf_printk(" secret_length:%d\n", secret_length);

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
        (void *)(ssl_hs_st_addr + SSL_HANDSHAKE_SERVER_HANDSHAKE_SECRET_);
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
        (void *)(s3_address + BSSL__SSL3_STATE_EXPORTER_SECRET);
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

    bpf_perf_event_output(ctx, &mastersecret_events, BPF_F_CURRENT_CPU,
                          mastersecret, sizeof(struct mastersecret_bssl_t));
    return 0;
}
