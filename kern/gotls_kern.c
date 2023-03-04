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

/* Copyright © 2022 Hengqi Chen */
#include "ecapture.h"
#include "gotls.h"

struct go_tls_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    int data_len;
    char comm[TASK_COMM_LEN];
    char data[MAX_DATA_SIZE_OPENSSL];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct go_tls_event);
    __uint(max_entries, 1);
} heap SEC(".maps");

static struct go_tls_event *get_gotls_event() {
    static const int zero = 0;
    struct go_tls_event *event;
    __u64 id;

    event = bpf_map_lookup_elem(&heap, &zero);
    if (!event) return NULL;

    id = bpf_get_current_pid_tgid();
    event->ts_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (__u32)id;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    return event;
}

// capture golang tls plaintext
// type recordType uint8
// writeRecordLocked(typ recordType, data []byte)
SEC("uprobe/gotls_text")
int gotls_text(struct pt_regs *ctx) {
    struct go_tls_event *event;
    s32 record_type, len;
    const char *str;
    record_type = (s32)go_get_argument(ctx, 2);
    str = (void *)go_get_argument(ctx, 3);
    len = (s32)go_get_argument(ctx, 4);

    debug_bpf_printk("gotls_text record_type:%d\n", record_type);
    if (record_type != recordTypeApplicationData) {
        return 0;
    }

    event = get_gotls_event();
    if (!event) {
        return 0;
    }

    int ret = bpf_probe_read_user_str(event->data, sizeof(event->data), str);
    if (ret < 0) {
        debug_bpf_printk(
            "gotls_text bpf_probe_read_user_str failed, ret:%d, str:%d\n", ret,
            str);
        return 0;
    }
    event->data_len = len;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                          sizeof(*event));
    return 0;
}