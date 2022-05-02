#include "ecapture.h"

struct event {
    u32 pid;
    u8 line[MAX_DATA_SIZE_BASH];
    u32 retval;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct event);
    __uint(max_entries, 1024);
} events_t SEC(".maps");
// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx) {
    s64 pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
#endif

    struct event event = {};
    event.pid = pid;
    // bpf_printk("!! uretprobe_bash_readline pid:%d",target_pid );
    bpf_probe_read(&event.line, sizeof(event.line), (void *)PT_REGS_RC(ctx));
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_map_update_elem(&events_t, &pid, &event, BPF_ANY);

    return 0;
}
SEC("uretprobe/bash_retval")
int uretprobe_bash_retval(struct pt_regs *ctx) {
    s64 pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    int retval = (int)PT_REGS_RC(ctx);

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
#endif

    struct event *event_p = bpf_map_lookup_elem(&events_t, &pid);

#ifndef KERNEL_LESS_5_2
    // if target_errno is 128 then we target all
    if (target_errno != BASH_ERRNO_DEFAULT && target_errno != retval) {
        if (event_p) bpf_map_delete_elem(&events_t, &pid);
        return 0;
    }
#endif

    if (event_p) {
        event_p->retval = retval;
        bpf_map_update_elem(&events_t, &pid, event_p, BPF_ANY);
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event_p,
                              sizeof(struct event));
    }
    return 0;
}
