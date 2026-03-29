// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Common struct, BPF maps, and helpers shared by all OpenSSL masterkey probes
// (openssl_masterkey.h, openssl_masterkey_3.0.h, openssl_masterkey_3.2.h).

#pragma once

#include "tls_constants.h"

struct mastersecret_t {
    /* TLS 1.2 or older */
    s32 version;
    u8 client_random[SSL3_RANDOM_SIZE];
    u8 master_key[MASTER_SECRET_MAX_LEN];

    /* TLS 1.3 */
    u32 cipher_id;
    u8 early_secret[EVP_MAX_MD_SIZE];
    u8 handshake_secret[EVP_MAX_MD_SIZE];
    u8 handshake_traffic_hash[EVP_MAX_MD_SIZE];
    u8 client_app_traffic_secret[EVP_MAX_MD_SIZE];
    u8 server_app_traffic_secret[EVP_MAX_MD_SIZE];
    u8 exporter_master_secret[EVP_MAX_MD_SIZE];
};

/***********************************************************
 * BPF Maps
 ***********************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
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

/***********************************************************
 * Common helpers
 ***********************************************************/

// Allocate a mastersecret_t on the BPF "heap" to work around the 512-byte
// stack limit.  Returns NULL on failure.
static __always_inline struct mastersecret_t *make_event(void) {
    u32 key_gen = 0;
    struct mastersecret_t *bpf_ctx =
        bpf_map_lookup_elem(&bpf_context_gen, &key_gen);
    if (!bpf_ctx)
        return 0;
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&bpf_context, &id, bpf_ctx, BPF_ANY);
    return bpf_map_lookup_elem(&bpf_context, &id);
}

