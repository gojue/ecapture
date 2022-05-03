#include "ecapture.h"

struct data_t {
    u64 pid;
    u64 timestamp;
    char query[MAX_DATA_SIZE_POSTGRES];
    char comm[TASK_COMM_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// https://github.com/postgres/postgres/blob/7b7ed046cb2ad9f6efac90380757d5977f0f563f/src/backend/tcop/postgres.c#L987-L992
// hook function exec_simple_query
// versions 10 - now
// static void exec_simple_query(const char *query_string)
SEC("uprobe/exec_simple_query")
int postgres_query(struct pt_regs *ctx) {

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
#endif

    struct data_t data = {};
    data.pid = pid;   // only process id
    data.timestamp = bpf_ktime_get_ns();

    char *sql_string= (char *)PT_REGS_PARM1(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&data.query, sizeof(data.query), sql_string);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}
