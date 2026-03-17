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

#include "nspr.h"

/***********************************************************
 * BPF probe function entry-points
 ***********************************************************/
// https://www-archive.mozilla.org/projects/nspr/reference/html/priofnc.html#19250

SEC("uprobe/PR_Write")
int probe_entry_SSL_write(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    debug_bpf_printk("nspr uprobe/PR_Write pid :%d\n", pid);

    if (!passes_filter(ctx)) {
        return 0;
    }

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&active_nspr_write_args_map, &current_pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/PR_Write")
int probe_ret_SSL_write(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    debug_bpf_printk("nspr uretprobe/PR_Write pid :%d\n", pid);

    if (!passes_filter(ctx)) {
        return 0;
    }

    const char** buf = bpf_map_lookup_elem(&active_nspr_write_args_map, &current_pid_tgid);
    if (buf != NULL) {
        process_nspr_data(ctx, current_pid_tgid, kNSPRWrite, *buf);
    }

    bpf_map_delete_elem(&active_nspr_write_args_map, &current_pid_tgid);
    return 0;
}

// Function signature being probed:
// PRInt32 PR_Read(PRFileDesc *fd, void *buf, PRInt32 amount)

SEC("uprobe/PR_Read")
int probe_entry_SSL_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    debug_bpf_printk("nspr uprobe/PR_Read pid :%d\n", pid);

    if (!passes_filter(ctx)) {
        return 0;
    }

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&active_nspr_read_args_map, &current_pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/PR_Read")
int probe_ret_SSL_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    debug_bpf_printk("nspr uretprobe/PR_Read pid :%d\n", pid);

    if (!passes_filter(ctx)) {
        return 0;
    }

    const char** buf = bpf_map_lookup_elem(&active_nspr_read_args_map, &current_pid_tgid);
    if (buf != NULL) {
        process_nspr_data(ctx, current_pid_tgid, kNSPRRead, *buf);
    }

    bpf_map_delete_elem(&active_nspr_read_args_map, &current_pid_tgid);
    return 0;
}
