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
#include "tc.h"


/***********************************************************
 * Internal structs and definitions
 ***********************************************************/

enum ssl_data_event_type { kSSLRead, kSSLWrite };
const u32 invalidFD = 0;
// BIO_TYPE_NONE
const u32 defaultBioType = 0;

struct ssl_data_event_t {
    enum ssl_data_event_type type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char data[MAX_DATA_SIZE_OPENSSL];
    s32 data_len;
    char comm[TASK_COMM_LEN];
    u32 fd;
    s32 version;
    u32 bio_type;
};

struct connect_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 fd;
    char sa_data[SA_DATA_LEN];
    char comm[TASK_COMM_LEN];
};

struct active_ssl_buf {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     * from ssl/ssl_local.h struct ssl_st
     */
    s32 version;
    u32 fd;
    u32 bio_type;
    const char* buf;
};

/***********************************************************
 * BPF MAPS
 ***********************************************************/


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} tls_events SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} connect_events SEC(".maps");


// Key is thread ID (from bpf_get_current_pid_tgid).
// Value is a pointer to the data buffer argument to SSL_write/SSL_read.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_read_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct ssl_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

// store ssl fd array for SSL_set_fd function hook.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 10240);
} ssl_st_fd SEC(".maps");


/***********************************************************
 * General helper functions
 ***********************************************************/

static __inline struct ssl_data_event_t* create_ssl_data_event(
    u64 current_pid_tgid) {
    u32 kZero = 0;
    struct ssl_data_event_t* event =
        bpf_map_lookup_elem(&data_buffer_heap, &kZero);
    if (event == NULL) {
        return NULL;
    }

    const u32 kMask32b = 0xffffffff;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = current_pid_tgid >> 32;
    event->tid = current_pid_tgid & kMask32b;
    event->fd = invalidFD;
    event->bio_type = defaultBioType;

    return event;
}

/***********************************************************
 * BPF syscall processing functions
 ***********************************************************/

static int process_SSL_data(struct pt_regs* ctx, u64 id,
                            enum ssl_data_event_type type, const char* buf,
                            u32 fd, s32 version, u32 bio_type) {
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0) {
        return 0;
    }

    struct ssl_data_event_t* event = create_ssl_data_event(id);
    if (event == NULL) {
        return 0;
    }

    event->type = type;
    event->fd = fd;
    event->bio_type = bio_type;
    event->version = version;
    // This is a max function, but it is written in such a way to keep older BPF
    // verifiers happy.
    event->data_len =
        (len < MAX_DATA_SIZE_OPENSSL ? (len & (MAX_DATA_SIZE_OPENSSL - 1))
                                     : MAX_DATA_SIZE_OPENSSL);
    bpf_probe_read_user(event->data, event->data_len, buf);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event,
                          sizeof(struct ssl_data_event_t));
    return 0;
}

static u32 process_BIO_type(u64 ssl_bio_addr) {
    u64 *ssl_bio_method_ptr, *ssl_bio_method_type_ptr;
    u64 ssl_bio_method_addr;
    u32 bio_type;
    int ret;

    // get ssl->bio->method
    ssl_bio_method_ptr = (u64 *)(ssl_bio_addr + BIO_ST_METHOD);
    ret = bpf_probe_read_user(&ssl_bio_method_addr, sizeof(ssl_bio_method_addr),
                              ssl_bio_method_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) process_BIO_type: bpf_probe_read ssl_bio_method_ptr failed, ret: %d\n",
            ret);
        return defaultBioType;
    }

    // get ssl->bio->method->type
    ssl_bio_method_type_ptr = (u64 *)(ssl_bio_method_addr + BIO_METHOD_ST_TYPE);
    ret = bpf_probe_read_user(&bio_type, sizeof(bio_type),
                              ssl_bio_method_type_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) process_BIO_type: bpf_probe_read ssl_bio_method_type_ptr failed, ret: %d\n",
            ret);
        return defaultBioType;
    }

    debug_bpf_printk("openssl process_BIO_type bio_type: %d\n", bio_type);
    return bio_type;
}

/***********************************************************
 * BPF probe function entry-points
 ***********************************************************/

// Function signature being probed:
// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs* ctx) {
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
    debug_bpf_printk("openssl uprobe/SSL_write pid: %d\n", pid);

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h

    u64 *ssl_ver_ptr, *ssl_wbio_ptr, *ssl_wbio_num_ptr;
    u64 ssl_version, ssl_wbio_addr, ssl_wbio_num_addr;
    int ret;

    ssl_ver_ptr = (u64 *)(ssl + SSL_ST_VERSION);
    ret = bpf_probe_read_user(&ssl_version, sizeof(ssl_version),
                              ssl_ver_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_ver_ptr failed, ret: %d\n",
            ret);
        return 0;
    }

    ssl_wbio_ptr = (u64 *)(ssl + SSL_ST_WBIO);
    ret = bpf_probe_read_user(&ssl_wbio_addr, sizeof(ssl_wbio_addr),
                              ssl_wbio_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_wbio_addr failed, ret: %d\n",
            ret);
        return 0;
    }

    // get ssl->bio->method->type
    u32 bio_type = process_BIO_type(ssl_wbio_addr);

    // get fd ssl->wbio->num
    ssl_wbio_num_ptr = (u64 *)(ssl_wbio_addr + BIO_ST_NUM);
    ret = bpf_probe_read_user(&ssl_wbio_num_addr, sizeof(ssl_wbio_num_addr),
                              ssl_wbio_num_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_wbio_num_ptr failed, ret: %d\n",
            ret);
        return 0;
    }
    u32 fd = (u32)ssl_wbio_num_addr;
    if (fd == 0) {
        u64 ssl_addr = (u64)ssl;
        u64 *fd_ptr = bpf_map_lookup_elem(&ssl_st_fd, &ssl_addr);
        if (fd_ptr) {
            fd = (u64)*fd_ptr;
        } else {
        }
    }
    debug_bpf_printk("openssl uprobe/SSL_write fd: %d, version: %d\n", fd, ssl_version);

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.fd = fd;
    active_ssl_buf_t.version = ssl_version;
    active_ssl_buf_t.buf = buf;
    active_ssl_buf_t.bio_type = bio_type;
    bpf_map_update_elem(&active_ssl_write_args_map, &current_pid_tgid,
                        &active_ssl_buf_t, BPF_ANY);

    return 0;
}

SEC("uretprobe/SSL_write")
int probe_ret_SSL_write(struct pt_regs* ctx) {
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
    debug_bpf_printk("openssl uretprobe/SSL_write pid: %d\n", pid);
    struct active_ssl_buf* active_ssl_buf_t =
        bpf_map_lookup_elem(&active_ssl_write_args_map, &current_pid_tgid);
    if (active_ssl_buf_t != NULL) {
        const char* buf;
        u32 fd = active_ssl_buf_t->fd;
        u32 bio_type = active_ssl_buf_t->bio_type;
        s32 version = active_ssl_buf_t->version;
        bpf_probe_read(&buf, sizeof(const char*), &active_ssl_buf_t->buf);
        process_SSL_data(ctx, current_pid_tgid, kSSLWrite, buf, fd, version, bio_type);
    }
    bpf_map_delete_elem(&active_ssl_write_args_map, &current_pid_tgid);
    return 0;
}

// Function signature being probed:
// int SSL_read(SSL *s, void *buf, int num)
SEC("uprobe/SSL_read")
int probe_entry_SSL_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;
    debug_bpf_printk("openssl uprobe/SSL_read pid: %d\n", pid);

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid) {
        return 0;
    }
#endif

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h
    // Get ssl_rbio pointer
    u64 *ssl_ver_ptr, *ssl_rbio_ptr, *ssl_rbio_num_ptr;
    u64 ssl_version, ssl_rbio_addr, ssl_rbio_num_addr;
    int ret;

    ssl_ver_ptr = (u64 *)(ssl + SSL_ST_VERSION);
    ret = bpf_probe_read_user(&ssl_version, sizeof(ssl_version),
                              ssl_ver_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_ver_ptr failed, ret: %d\n",
            ret);
        return 0;
    }

    ssl_rbio_ptr = (u64 *)(ssl + SSL_ST_RBIO);
    ret = bpf_probe_read_user(&ssl_rbio_addr, sizeof(ssl_rbio_addr),
                              ssl_rbio_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_rbio_ptr failed, ret: %d\n",
            ret);
        return 0;
    }

    // get ssl->bio->method->type
    u32 bio_type = process_BIO_type(ssl_rbio_addr);

    // get fd ssl->rbio->num
    ssl_rbio_num_ptr = (u64 *)(ssl_rbio_addr + BIO_ST_NUM);
    ret = bpf_probe_read_user(&ssl_rbio_num_addr, sizeof(ssl_rbio_num_addr),
                              ssl_rbio_num_ptr);
    if (ret) {
        debug_bpf_printk(
            "(OPENSSL) bpf_probe_read ssl_rbio_num_ptr failed, ret: %d\n",
            ret);
        return 0;
    }
    u32 fd = (u32)ssl_rbio_num_addr;
    if (fd == 0) {
        u64 ssl_addr = (u64)ssl;
        u64 *fd_ptr = bpf_map_lookup_elem(&ssl_st_fd, &ssl_addr);
        if (fd_ptr) {
            fd = (u64)*fd_ptr;
        } else {
        }
    }
    debug_bpf_printk("openssl uprobe/SSL_read fd: %d, version: %d\n", fd, ssl_version);

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.fd = fd;
    active_ssl_buf_t.version = ssl_version;
    active_ssl_buf_t.buf = buf;
    active_ssl_buf_t.bio_type = bio_type;
    bpf_map_update_elem(&active_ssl_read_args_map, &current_pid_tgid,
                        &active_ssl_buf_t, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ret_SSL_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;
    debug_bpf_printk("openssl uretprobe/SSL_read pid: %d\n", pid);

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid) {
        return 0;
    }
#endif

    struct active_ssl_buf* active_ssl_buf_t =
        bpf_map_lookup_elem(&active_ssl_read_args_map, &current_pid_tgid);
    if (active_ssl_buf_t != NULL) {
        const char* buf;
        u32 fd = active_ssl_buf_t->fd;
        u32 bio_type = active_ssl_buf_t->bio_type;
        s32 version = active_ssl_buf_t->version;
        bpf_probe_read(&buf, sizeof(const char*), &active_ssl_buf_t->buf);
        process_SSL_data(ctx, current_pid_tgid, kSSLRead, buf, fd, version, bio_type);
    }
    bpf_map_delete_elem(&active_ssl_read_args_map, &current_pid_tgid);
    return 0;
}

// libc : int __connect (int fd, __CONST_SOCKADDR_ARG addr, socklen_t len)
// kernel : int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
SEC("kprobe/sys_connect")
int probe_connect(struct pt_regs* ctx) {
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

    u32 fd = (u32)PT_REGS_PARM1(ctx);
    struct sockaddr* saddr = (struct sockaddr*)PT_REGS_PARM2(ctx);
    if (!saddr) {
        return 0;
    }
    sa_family_t address_family = 0;
    bpf_probe_read_user(&address_family, sizeof(address_family),
                        &saddr->sa_family);

    if (address_family != AF_INET) {
        return 0;
    }

    debug_bpf_printk("@ sockaddr FM :%d\n", address_family);

    struct connect_event_t conn;
    __builtin_memset(&conn, 0, sizeof(conn));
    conn.timestamp_ns = bpf_ktime_get_ns();
    conn.pid = pid;
    conn.tid = current_pid_tgid;
    conn.fd = fd;
    bpf_probe_read_user(&conn.sa_data, SA_DATA_LEN, &saddr->sa_data);
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));

    bpf_perf_event_output(ctx, &connect_events, BPF_F_CURRENT_CPU, &conn,
                          sizeof(struct connect_event_t));
    return 0;
}



// int SSL_set_fd(SSL *s, int fd)
// int SSL_set_rfd(SSL *s, int fd)
// int SSL_set_wfd(SSL *s, int fd)
SEC("uprobe/SSL_set_fd")
int probe_SSL_set_fd(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    u64 ssl_addr = (u64)PT_REGS_PARM1(ctx);
    u64 fd = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_st_fd, &ssl_addr, &fd, BPF_ANY);
    debug_bpf_printk("SSL_set_fd hook!!, ssl_addr: %d, fd: %d\n", ssl_addr, fd);
    return 0;
}
