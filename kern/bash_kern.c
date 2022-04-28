#include "ecapture.h"

struct event {
    u32 pid;
    u8 line[80];
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

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

    struct event event;
    //    bpf_printk("!! uretprobe_bash_readline pid:%d",target_pid );
    event.pid = pid;
    bpf_probe_read(&event.line, sizeof(event.line), (void *)PT_REGS_RC(ctx));

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                          sizeof(event));

    return 0;
}
