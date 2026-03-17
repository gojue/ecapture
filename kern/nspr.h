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

#ifndef ECAPTURE_NSPR_H
#define ECAPTURE_NSPR_H

#include "ecapture.h"

/***********************************************************
 * Internal structs and definitions
 ***********************************************************/

enum nspr_data_event_type { kNSPRRead, kNSPRWrite };

struct nspr_data_event_t {
    enum nspr_data_event_type type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char data[MAX_DATA_SIZE_OPENSSL];
    s32 data_len;
    char comm[TASK_COMM_LEN];
};

/***********************************************************
 * BPF MAPS
 ***********************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} nspr_events SEC(".maps");

// Key is thread ID (from bpf_get_current_pid_tgid).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, const char*);
    __uint(max_entries, 1024);
} active_nspr_read_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, const char*);
    __uint(max_entries, 1024);
} active_nspr_write_args_map SEC(".maps");

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct nspr_data_event_t);
    __uint(max_entries, 1);
} nspr_data_buffer_heap SEC(".maps");

/***********************************************************
 * General helper functions
 ***********************************************************/

static __inline struct nspr_data_event_t* create_nspr_data_event(u64 current_pid_tgid) {
    u32 kZero = 0;
    struct nspr_data_event_t* event = bpf_map_lookup_elem(&nspr_data_buffer_heap, &kZero);
    if (event == NULL) {
        return NULL;
    }

    const u32 kMask32b = 0xffffffff;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = current_pid_tgid >> 32;
    event->tid = current_pid_tgid & kMask32b;
    return event;
}

/***********************************************************
 * BPF syscall processing functions
 ***********************************************************/

static int process_nspr_data(struct pt_regs* ctx, u64 id, enum nspr_data_event_type type, const char* buf) {
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0) {
        return 0;
    }

    struct nspr_data_event_t* event = create_nspr_data_event(id);
    if (event == NULL) {
        return 0;
    }

    event->type = type;
    // This is a max function, but it is written in such a way to keep older BPF
    // verifiers happy.
    event->data_len = (len < MAX_DATA_SIZE_OPENSSL ? (len & (MAX_DATA_SIZE_OPENSSL - 1)) : MAX_DATA_SIZE_OPENSSL);
    bpf_probe_read_user(event->data, event->data_len, buf);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_perf_event_output(ctx, &nspr_events, BPF_F_CURRENT_CPU, event, sizeof(struct nspr_data_event_t));
    return 0;
}

#endif
