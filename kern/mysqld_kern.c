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

#define DISPATCH_COMMAND_V57_FAILED -2

struct data_t {
    u64 pid;
    u64 timestamp;
    char query[MAX_DATA_SIZE_MYSQL];
    u64 alllen;
    u64 len;
    char comm[TASK_COMM_LEN];
    s8 retval;  // dispatch_command return value
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct data_t);
    __uint(max_entries, 1024);
} sql_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

SEC("uprobe/dispatch_command")
int mysql56_query(struct pt_regs *ctx) {
    /*
    Trace only packets with enum_server_command == COM_QUERY
    https://dev.mysql.com/doc/internals/en/com-query.html COM_QUERT command 03
    */
    // MYSQL57
    //  https://github.com/MariaDB/server/blob/b5852ffbeebc3000982988383daeefb0549e058a/sql/sql_parse.h#L112
    //  dispatch_command_return dispatch_command(enum enum_server_command
    //  command, THD *thd,
    //                                                 char* packet, uint
    //                                                 packet_length, bool
    //                                                 blocking = true);

    // https://blog.csdn.net/u010502974/article/details/96362601
    // mysql_parse
    u64 command = (u64)PT_REGS_PARM1(ctx);
    if (command != COM_QUERY) {
        return 0;
    }

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
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

    u64 len = (u64)PT_REGS_PARM4(ctx);
    if (len < 0) {
        return 0;
    }

    struct data_t data = {};
    data.pid = pid;     // only process id
    data.alllen = len;  // origin query sql length
    data.timestamp = bpf_ktime_get_ns();
    data.retval = -1;
    len = (len < MAX_DATA_SIZE_MYSQL ? (len & (MAX_DATA_SIZE_MYSQL - 1)) : MAX_DATA_SIZE_MYSQL);
    data.len = len;  // only process id
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_probe_read_user(&data.query, len, (void *)PT_REGS_PARM3(ctx));

    bpf_map_update_elem(&sql_hash, &pid, &data, BPF_ANY);
    //    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
    //    &data,sizeof(data));
    return 0;
}

SEC("uretprobe/dispatch_command")
int mysql56_query_return(struct pt_regs *ctx) {
    // https://github.com/MariaDB/server/blob/b5852ffbeebc3000982988383daeefb0549e058a/sql/sql_parse.h#L112
    // enum dispatch_command_return
    //       {
    //         DISPATCH_COMMAND_SUCCESS=0,
    //         DISPATCH_COMMAND_CLOSE_CONNECTION= 1,
    //         DISPATCH_COMMAND_WOULDBLOCK= 2
    //       };
    // dispatch_command_return dispatch_command(enum enum_server_command
    // command, THD *thd,
    //                                                char* packet, uint
    //                                                packet_length, bool
    //                                                blocking = true);

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
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

    s8 command_return = (u64)PT_REGS_RC(ctx);
    struct data_t *data = bpf_map_lookup_elem(&sql_hash, &pid);
    if (!data) {
        return 0;  // missed start
    }
    debug_bpf_printk("mysql query:%s\n", data->query);
    data->retval = command_return;
    debug_bpf_printk("mysql query return :%d\n", command_return);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(struct data_t));
    return 0;
}

// mysql 8.0
/*
https://github.com/mysql/mysql-server/blob/8.0/sql/sql_parse.h
bool dispatch_command(THD *thd, const COM_DATA *com_data,
                      enum enum_server_command command);

// https://github.com/mysql/mysql-server/blob/8.0/include/mysql/com_data.h

struct PS_PARAM {
  unsigned char null_bit;
  //  enum enum_field_types type;
    int type;
  unsigned char unsigned_type;
  const unsigned char *value;
  unsigned long length;
  const unsigned char *name;
  unsigned long name_length;
};

// for 5.7
struct COM_QUERY_DATA {
  const char *query;
  unsigned int length;
  PS_PARAM *parameters;         //  for 8.0
  unsigned long parameter_count;    // for 8.0
};
*/

// mysql 5.7
// https://github.com/mysql/mysql-server/blob/5.7/include/mysql/com_data.h
struct COM_QUERY_DATA {
    const char *query;
    unsigned int length;
    //  struct PS_PARAM *parameters;    TODO
    //  unsigned long parameter_count;
};

// https://github.com/mysql/mysql-server/blob/5.7/sql/sql_parse.h
// bool dispatch_command(THD *thd, const COM_DATA *com_data,
//                       enum enum_server_command command);
//  hook function _Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command at
//  version:8.0.28-0ubuntu0.20.04.3
//
SEC("uprobe/dispatch_command_57")
int mysql57_query(struct pt_regs *ctx) {
    u64 command = (u64)PT_REGS_PARM3(ctx);
    if (command != COM_QUERY) {
        return 0;
    }

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
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

    u64 len = 0;
    struct data_t data = {};
    data.pid = pid;  // only process id
    data.timestamp = bpf_ktime_get_ns();

    void *st = (void *)PT_REGS_PARM2(ctx);
    struct COM_QUERY_DATA query;
    bpf_probe_read_user(&query, sizeof(query), st);
    bpf_probe_read_user(&data.query, sizeof(data.query), query.query);
    bpf_probe_read_user(&data.alllen, sizeof(data.alllen), &query.length);
    len = data.alllen;
    len = (len < MAX_DATA_SIZE_MYSQL ? (len & (MAX_DATA_SIZE_MYSQL - 1)) : MAX_DATA_SIZE_MYSQL);
    data.len = len;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_map_update_elem(&sql_hash, &pid, &data, BPF_ANY);
    //    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
    //    &data,sizeof(data));
    return 0;
}

//@retval
//    0   ok
//  @retval
//    1   request of thread shutdown, i. e. if command is
//        COM_QUIT
SEC("uretprobe/dispatch_command_57")
int mysql57_query_return(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
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

    u8 command_return = (u64)PT_REGS_RC(ctx);
    struct data_t *data = bpf_map_lookup_elem(&sql_hash, &pid);
    if (!data) {
        return 0;  // missed start
    }
    debug_bpf_printk("mysql57+ query:%s\n", data->query);
    debug_bpf_printk("mysql57+ query return :%d\n", command_return);
    if (command_return == 1) {
        data->retval = DISPATCH_COMMAND_V57_FAILED;
    } else {
        data->retval = command_return;
    }
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(struct data_t));

    return 0;
}