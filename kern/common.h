#ifndef ECAPTURE_COMMON_H
#define ECAPTURE_COMMON_H

#define TASK_COMM_LEN 16
#define MAX_DATA_SIZE_OPENSSL 1024 * 4
#define MAX_DATA_SIZE_MYSQL 256
#define COM_QUERY 3 //enum_server_command, via https://dev.mysql.com/doc/internals/en/com-query.html COM_QUERT command 03


// Optional Target PID
const volatile u64 target_pid = 0;


char __license[] SEC("license") = "Dual MIT/GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

#endif