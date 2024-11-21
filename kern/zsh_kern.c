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

SEC("uretprobe/zsh_zleentry")
int uretprobe_zsh_zleentry(struct pt_regs *ctx) {
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
    struct event event = {};
    event.pid = pid;
    event.uid = uid;
    event.type = ZSH_EVENT_TYPE_READLINE;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));   
    bpf_probe_read_user(&event.line, sizeof(event.line),(void *)PT_REGS_RC(ctx));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(struct event));
    return 0;
}