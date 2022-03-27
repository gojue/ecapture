#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

struct data_t {
    u64 pid;
    u64 timestamp;
    char query[MAX_DATA_SIZE_MYSQL];
    u64 alllen;
    u64 len;
    char comm[TASK_COMM_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("uprobe/dispatch_command")
int mysql56_query(struct pt_regs *ctx) {
    /*
    Trace only packets with enum_server_command == COM_QUERY
    https://dev.mysql.com/doc/internals/en/com-query.html COM_QUERT command 03
    */
    //MYSQL57
    // https://github.com/MariaDB/server/blob/b5852ffbeebc3000982988383daeefb0549e058a/sql/sql_parse.h#L112
    // dispatch_command_return dispatch_command(enum enum_server_command command, THD *thd,
    //                                                char* packet, uint packet_length, bool blocking = true);

    // https://blog.csdn.net/u010502974/article/details/96362601
    //mysql_parse
    // TODO change to macros
    uint64_t command  = (uint64_t)PT_REGS_PARM1(ctx);
    if (command != COM_QUERY) {
        return 0;
    }

    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

    uint64_t len  = (uint64_t)PT_REGS_PARM4(ctx);
    if (len < 0) {
        return 0;
    }

    struct data_t data = {};
    data.pid = pid;   // only process id
    data.alllen = len;   // origin query sql length
    data.timestamp = bpf_ktime_get_ns();

    len = (len < MAX_DATA_SIZE_MYSQL ? (len & (MAX_DATA_SIZE_MYSQL - 1)) : MAX_DATA_SIZE_MYSQL);
    data.len = len;   // only process id
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_probe_read_user(&data.query, len, (void*)PT_REGS_PARM3(ctx));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data,sizeof(data));
    return 0;
}
