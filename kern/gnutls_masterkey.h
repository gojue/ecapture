// Author: yuweizzz <yuwei764969238@gmail.com>.
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

// Ref:
// https://github.com/gnutls/gnutls/blob/3.7.9/lib/gnutls_int.h
// 
// typedef struct gnutls_session_int *gnutls_session_t;
// struct gnutls_session_int {
//     security_parameters_st security_parameters;
//     record_parameters_st *record_parameters[MAX_EPOCH_INDEX];
//     internals_st internals;
//     gnutls_key_st key;
// };
// 
// gnutls_session_int --> security_parameters_st
// struct security_parameters_st {
//     // ignore
//     // ...
//     const mac_entry_st *prf;
//     uint8_t master_secret[GNUTLS_MASTER_SIZE];
//     uint8_t client_random[GNUTLS_RANDOM_SIZE];
//     // ignore
//     // ...
//     const version_entry_st *pversion;
// };
// 
// gnutls_session_int --> security_parameters_st --> mac_entry_st
// typedef struct mac_entry_st {
//     // ignore
//     // ...
//     gnutls_mac_algorithm_t id;
//     // ignore
//     // ...
// } mac_entry_st;
// 
// gnutls_session_int --> security_parameters_st -> version_entry_st
// typedef struct {
//     // ignore
//     // ...
//     gnutls_protocol_t id;	/* gnutls internal version number */
//     // ignore
//     // ...
// } version_entry_st;
// 
// gnutls_session_int --> gnutls_key_st
// struct gnutls_key_st {
//     // ignore
//     // ...
//     union {
//         struct {
//             // ignore
//             // ...
//             uint8_t hs_ckey[MAX_HASH_SIZE]; /* client_hs_traffic_secret */
//             uint8_t hs_skey[MAX_HASH_SIZE]; /* server_hs_traffic_secret */
//             uint8_t ap_ckey[MAX_HASH_SIZE]; /* client_ap_traffic_secret */
//             uint8_t ap_skey[MAX_HASH_SIZE]; /* server_ap_traffic_secret */
//             uint8_t ap_expkey[MAX_HASH_SIZE]; /* {early_,}exporter_master_secret */
//             // ignore
//             // ...
//         } tls13; /* tls1.3 */
// 
//         /* Follow the SSL3.0 and TLS1.2 key exchanges */
//         struct {
//             // ignore
//             // ...
//         } tls12; /* from ssl3.0 to tls12 */
//     } proto;
//     // ignore
//     // ...
// };
//

#define GNUTLS_RANDOM_SIZE 32
#define GNUTLS_MASTER_SIZE 48
#define MAX_HASH_SIZE 64

struct gnutls_mastersecret_st {
    u32 version;
    /* from ssl3.0 to tls1.2 */
    u8 client_random[GNUTLS_RANDOM_SIZE];
    u8 master_secret[GNUTLS_MASTER_SIZE];

    /* tls1.3 */
    u32 cipher_id;
    u8 client_handshake_secret[MAX_HASH_SIZE];
    u8 server_handshake_secret[MAX_HASH_SIZE];
    u8 client_traffic_secret[MAX_HASH_SIZE];
    u8 server_traffic_secret[MAX_HASH_SIZE];
    u8 exporter_master_secret[MAX_HASH_SIZE];
};

// #define GNUTLS_MAC_SHA256 6
// #define GNUTLS_MAC_SHA384 7

#define GNUTLS_SSL3 1
#define GNUTLS_TLS1_0 2
#define GNUTLS_TLS1 GNUTLS_TLS1_0
#define GNUTLS_TLS1_1 3
#define GNUTLS_TLS1_2 4
#define GNUTLS_TLS1_3 5
#define GNUTLS_DTLS1_0 201
#define GNUTLS_DTLS1_2 202

/////////////////////////BPF MAPS ////////////////////////////////

// bpf map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} mastersecret_gnutls_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1024);
} gnutls_session_maps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct gnutls_mastersecret_st);
    __uint(max_entries, 2048);
} bpf_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct gnutls_mastersecret_st);
    __uint(max_entries, 1);
} bpf_context_gen SEC(".maps");

/////////////////////////COMMON FUNCTIONS ////////////////////////////////
// 这个函数用来规避512字节栈空间限制，通过在堆上创建内存的方式，避开限制
static __always_inline struct gnutls_mastersecret_st *make_event() {
    u32 key_gen = 0;
    struct gnutls_mastersecret_st *bpf_ctx = bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
    if (!bpf_ctx) return 0;
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bpf_context, &id, bpf_ctx, BPF_ANY);
    return bpf_map_lookup_elem(&bpf_context, &id);
}

/////////////////////////BPF FUNCTIONS ////////////////////////////////
SEC("uprobe/gnutls_handshake")
int uprobe_gnutls_master_key(struct pt_regs *ctx) {
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
    u64 gnutls_session_addr = (u64)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&gnutls_session_maps, &current_pid_tgid, &gnutls_session_addr, BPF_ANY);
    debug_bpf_printk("gnutls uprobe/gnutls_handshake PID: %d, gnutls_session_addr: %d\n", pid, gnutls_session_addr);
    return 0;
}

SEC("uretprobe/gnutls_handshake")
int uretprobe_gnutls_master_key(struct pt_regs *ctx) {
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

    u8 handshake_return = (u8)PT_REGS_RC(ctx);
    if (handshake_return != 0) {
        // handshake failed
        debug_bpf_printk("gnutls uretprobe/gnutls_handshake PID: %d, handshake failed, ret: %d\n", pid, handshake_return);
        return 0;
    }
    debug_bpf_printk("gnutls uretprobe/gnutls_handshake PID: %d\n", pid);

    u64 *gnutls_session_addr_ptr = bpf_map_lookup_elem(&gnutls_session_maps, &current_pid_tgid);
    if (!gnutls_session_addr_ptr) {
        debug_bpf_printk("gnutls uretprobe/gnutls_handshake, lookup for gnutls_session_addr failed\n");
        return 0;
    }

    u64 gnutls_session_addr = (u64) *gnutls_session_addr_ptr;
    debug_bpf_printk("gnutls uretprobe/gnutls_handshake, gnutls_session_addr: %d\n", gnutls_session_addr);

    // ssl_version
    u64 pversion_addr;
    int ret = bpf_probe_read_user(&pversion_addr, sizeof(pversion_addr),
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_SECURITY_PARAMETERS + SECURITY_PARAMETERS_ST_PVERSION));
    if (ret) {
        debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get pversion_addr failed, ret: %d\n", ret);
        return 0;
    }
    int ssl_version;
    ret = bpf_probe_read_user(&ssl_version, sizeof(ssl_version), (void *)(pversion_addr + VERSION_ENTRY_ST_ID));
    if (ret) {
        debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get ssl_version failed, ret: %d\n", ret);
        return 0;
    }
    debug_bpf_printk("ssl_version: %d\n", ssl_version);

    /* from ssl3.0 to tls1.2 */
    if ((ssl_version >= GNUTLS_SSL3 && ssl_version <= GNUTLS_TLS1_2) ||
        (ssl_version >= GNUTLS_DTLS1_0 && ssl_version <= GNUTLS_DTLS1_2)) {
        struct gnutls_mastersecret_st *mastersecret = make_event();
        if (!mastersecret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, mastersecret is null\n");
            return 0;
        }
        mastersecret->version = ssl_version;
        ret = bpf_probe_read_user(&mastersecret->client_random, sizeof(mastersecret->client_random),
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_SECURITY_PARAMETERS_CLIENT_RANDOM));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get client_random failed, ret: %d\n", ret);
            return 0;
        }
        ret = bpf_probe_read_user(&mastersecret->master_secret, sizeof(mastersecret->master_secret), 
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_SECURITY_PARAMETERS_MASTER_SECRET));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get master_secret failed, ret: %d\n", ret);
            return 0;
        }
        bpf_perf_event_output(ctx, &mastersecret_gnutls_events, BPF_F_CURRENT_CPU, mastersecret, sizeof(struct gnutls_mastersecret_st));
    }

    // tls 1.3
    if (ssl_version == GNUTLS_TLS1_3) {
        struct gnutls_mastersecret_st *mastersecret = make_event();
        if (!mastersecret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, mastersecret is null\n");
            return 0;
        }
        mastersecret->version = ssl_version;
        // mac cipher id
        u64 prf_addr;
        ret = bpf_probe_read_user(&prf_addr, sizeof(prf_addr),
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_SECURITY_PARAMETERS_PRF));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get prf failed, ret: %d\n", ret);
            return 0;
        }
        int mac_cipher_id;
        ret = bpf_probe_read_user(&mac_cipher_id, sizeof(mac_cipher_id), (void *)(prf_addr + MAC_ENTRY_ST_ID));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get mac_cipher_id failed, ret: %d\n", ret);
            return 0;
        }
        debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get mac_cipher_id ret: %d\n", mac_cipher_id);
        mastersecret->cipher_id = mac_cipher_id;
        ret = bpf_probe_read_user(&mastersecret->client_random, sizeof(mastersecret->client_random),
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_SECURITY_PARAMETERS_CLIENT_RANDOM));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get client_random failed, ret: %d\n", ret);
            return 0;
        }
        ret = bpf_probe_read_user(&mastersecret->client_handshake_secret, sizeof(mastersecret->client_handshake_secret),
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_KEY_PROTO_TLS13_HS_CKEY));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get client_handshake_secret failed, ret: %d\n", ret);
            return 0;
        }
        ret = bpf_probe_read_user(&mastersecret->server_handshake_secret, sizeof(mastersecret->server_handshake_secret),
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_KEY_PROTO_TLS13_HS_SKEY));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get server_handshake_secret failed, ret: %d\n", ret);
            return 0;
        }
        ret = bpf_probe_read_user(&mastersecret->client_traffic_secret, sizeof(mastersecret->client_traffic_secret),
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_KEY_PROTO_TLS13_AP_CKEY));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get client_traffic_secret failed, ret: %d\n", ret);
            return 0;
        }
        ret = bpf_probe_read_user(&mastersecret->server_traffic_secret, sizeof(mastersecret->server_traffic_secret),
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_KEY_PROTO_TLS13_AP_SKEY));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get server_traffic_secret failed, ret: %d\n", ret);
            return 0;
        }
        ret = bpf_probe_read_user(&mastersecret->exporter_master_secret, sizeof(mastersecret->exporter_master_secret),
                                  (void *)(gnutls_session_addr + GNUTLS_SESSION_INT_KEY_PROTO_TLS13_AP_EXPKEY));
        if (ret) {
            debug_bpf_printk("gnutls uretprobe/gnutls_handshake, get exporter_master_secret failed, ret: %d\n", ret);
            return 0;
        }
        bpf_perf_event_output(ctx, &mastersecret_gnutls_events, BPF_F_CURRENT_CPU, mastersecret, sizeof(struct gnutls_mastersecret_st));
    }

    return 0;
}
