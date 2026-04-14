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
#define PATH_MAX_LEN 256

/*
 * RFC 5246 : https://datatracker.ietf.org/doc/html/rfc5246#section-6.2
 * length
 *    The length (in bytes) of the following TLSPlaintext.fragment.  The length MUST NOT exceed 2^14.
 *
 * OpenSSL : SSL3_RT_MAX_PLAIN_LENGTH (16384). These functions will only accept a value in the range 512 - SSL3_RT_MAX_PLAIN_LENGTH.
 * https://docs.openssl.org/1.1.1/man3/SSL_CTX_set_split_send_fragment/#description
 */
#define MAX_DATA_SIZE_OPENSSL (1024 * 16)
#define MAX_DATA_SIZE_MYSQL 256
#define MAX_DATA_SIZE_POSTGRES 256
#define MAX_DATA_SIZE_BASH 256
#define MAX_DATA_SIZE_ZSH 256

// enum_server_command, via
// https://dev.mysql.com/doc/internals/en/com-query.html COM_QUERY command 03
#define COM_QUERY 3

#define AF_INET 2
#define AF_INET6 10
#define BASH_ERRNO_DEFAULT 128

#define BASH_EVENT_TYPE_READLINE 0
#define BASH_EVENT_TYPE_RETVAL 1
#define BASH_EVENT_TYPE_EXIT_OR_EXEC 2
#define ZSH_EVENT_TYPE_READLINE 4
///////// for TC & XDP ebpf programs in tc.h
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet        */
#define ETH_P_IPV6 0x86DD
#define SKB_MAX_DATA_SIZE 2048

// .rodata section bug via : https://github.com/gojue/ecapture/issues/39

// Kernel version less than 5.2
const volatile u64 less52 = 1;
// Optional Target PID and UID
const volatile u64 target_pid = 0;
const volatile u64 target_uid = 0;
const volatile u64 target_errno = BASH_ERRNO_DEFAULT;
// Optional Target cgroup ID (0 means no cgroup filtering)
// bpf_get_current_cgroup_id() requires kernel >= 4.18
const volatile u64 target_cgroup_id = 0;



// fix  4.19.91-27.7.al7.x86_64/source/include/linux/kernel.h:140:9: warning: 'roundup' macro redefined
#ifndef roundup
#define roundup(x, y)                    \
    ({                                   \
        typeof(y) __y = y;               \
        (((x) + (__y - 1)) / __y) * __y; \
    })
#endif

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

// Strip ARM64 Pointer Authentication Code (PAC) bits from pointers read from
// user-space memory. On ARM64 with PAC enabled (common on Android 16+),
// pointers stored in structures may contain PAC signature bits in the upper
// bits. These must be cleared before using the pointer value as an address
// in subsequent bpf_probe_read_user() calls.
// On non-ARM64 architectures, this is a no-op.
#ifdef __aarch64__
#define STRIP_PAC(addr) ((addr) & 0x0000FFFFFFFFFFFFULL)
#else
#define STRIP_PAC(addr) (addr)
#endif

#endif
