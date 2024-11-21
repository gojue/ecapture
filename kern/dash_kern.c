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

struct event {
    u32 type;
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u8 line[MAX_DATA_SIZE_DASH];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("uprobe/dash_read")
int uprobe_dash_read(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
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
    u32 fd = (u32)PT_REGS_PARM1(ctx);
    if (fd == 0) {
        struct event event = {};
        event.pid = pid;
        event.uid = uid;
        event.type = DASH_EVENT_TYPE_READLINE;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        bpf_probe_read_user(&event.line, sizeof(event.line),(void *)PT_REGS_PARM2(ctx));
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(struct event));
    }
    return 0;
}