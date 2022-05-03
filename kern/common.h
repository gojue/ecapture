#ifndef ECAPTURE_COMMON_H
#define ECAPTURE_COMMON_H

#ifdef DEBUG_PRINT
#define debug_bpf_printk(fmt, ...)                     \
    do {                                               \
        char s[] = fmt;                                \
        bpf_trace_printk(s, sizeof(s), ##__VA_ARGS__); \
    } while (0)
#else
#define debug_bpf_printk(fmt, ...)
#endif

#define TASK_COMM_LEN 16
#define MAX_DATA_SIZE_OPENSSL 1024 * 4
#define MAX_DATA_SIZE_MYSQL 256
#define MAX_DATA_SIZE_POSTGRES 256
#define MAX_DATA_SIZE_BASH 256

// enum_server_command, via
// https://dev.mysql.com/doc/internals/en/com-query.html COM_QUERT command 03
#define COM_QUERY 3

#define AF_INET 2
#define AF_INET6 10
#define SA_DATA_LEN 14
#define BASH_ERRNO_DEFAULT 128

// Optional Target PID
// .rodata section bug via : https://github.com/ehids/ecapture/issues/39
#ifndef KERNEL_LESS_5_2
const volatile u64 target_pid = 0;
const volatile int target_errno = BASH_ERRNO_DEFAULT;
#else
// u64 target_pid = 0;
#endif

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

#endif
