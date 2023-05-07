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

/* Copyright © 2022 Hengqi Chen */
#include "ecapture.h"
#include "go_argument.h"
#include "tc.h"

#define GOTLS_RANDOM_SIZE 32

// max length is "CLIENT_HANDSHAKE_TRAFFIC_SECRET"=31
#define MASTER_SECRET_KEY_LEN 32
#define EVP_MAX_MD_SIZE 64
#define GOTLS_EVENT_TYPE_WRITE 0
#define GOTLS_EVENT_TYPE_READ 1

// // TLS record types in golang tls package
#define recordTypeApplicationData 23

struct go_tls_event {
    u64 ts_ns;
    u32 pid;
    u32 tid;
    s32 data_len;
    u8 event_type;
    char comm[TASK_COMM_LEN];
    char data[MAX_DATA_SIZE_OPENSSL];
};

struct mastersecret_gotls_t {
    u8 label[MASTER_SECRET_KEY_LEN];
    u8 labellen;
    u8 client_random[EVP_MAX_MD_SIZE];
    u8 client_random_len;
    u8 secret_[EVP_MAX_MD_SIZE];
    u8 secret_len;
};

/////////////////////////BPF MAPS ////////////////////////////////

// bpf map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} mastersecret_go_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct go_tls_event);
    __uint(max_entries, 2048);
} gte_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct go_tls_event);
    __uint(max_entries, 1);
} gte_context_gen SEC(".maps");

static __always_inline struct go_tls_event *get_gotls_event() {
    u32 zero = 0;
    struct go_tls_event *event = bpf_map_lookup_elem(&gte_context_gen, &zero);
    if (!event) return 0;

    u64 id = bpf_get_current_pid_tgid();
    event->ts_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (__u32)id;
    event->event_type = GOTLS_EVENT_TYPE_WRITE;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_map_update_elem(&gte_context, &id, event, BPF_ANY);
    return bpf_map_lookup_elem(&gte_context, &id);
}

static __always_inline int gotls_write(struct pt_regs *ctx,
                                       bool is_register_abi) {
    s32 record_type, len;
    const char *str;
    void *record_type_ptr;
    void *len_ptr;
    record_type_ptr = (void *)go_get_argument(ctx, is_register_abi, 2);
    bpf_probe_read_kernel(&record_type, sizeof(record_type),
                          (void *)&record_type_ptr);
    str = (void *)go_get_argument(ctx, is_register_abi, 3);
    len_ptr = (void *)go_get_argument(ctx, is_register_abi, 4);
    bpf_probe_read_kernel(&len, sizeof(len), (void *)&len_ptr);

    debug_bpf_printk("gotls_write record_type:%d\n", record_type);
    if (record_type != recordTypeApplicationData) {
        return 0;
    }

    struct go_tls_event *event = get_gotls_event();
    if (!event) {
        return 0;
    }

    event->data_len = len;
    int ret =
        bpf_probe_read_user(&event->data, sizeof(event->data), (void *)str);
    if (ret < 0) {
        debug_bpf_printk(
            "gotls_write bpf_probe_read_user_str failed, ret:%d, str:%d\n", ret,
            str);
        return 0;
    }
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                          sizeof(struct go_tls_event));
    return 0;
}

// capture golang tls plaintext, supported golang stack-based ABI (go version
// >= 1.17) type recordType uint8 writeRecordLocked(typ recordType, data []byte)
SEC("uprobe/gotls_write_register")
int gotls_write_register(struct pt_regs *ctx) { return gotls_write(ctx, true); }

// capture golang tls plaintext, supported golang stack-based ABI (go version
// < 1.17) type recordType uint8 writeRecordLocked(typ recordType, data []byte)
SEC("uprobe/gotls_write_stack")
int gotls_write_stack(struct pt_regs *ctx) { return gotls_write(ctx, false); }

// func (c *Conn) Read(b []byte) (int, error)
static __always_inline int gotls_read(struct pt_regs *ctx,
                                      bool is_register_abi) {
    s32 record_type, len, ret_len;
    const char *str;
    void *len_ptr, *ret_len_ptr;

    // golang
    // uretprobe的实现，为选择目标函数中，汇编指令的RET指令地址，即调用子函数的返回后的触发点，此时，此函数参数等地址存放在SP(stack
    // Point)上，故使用stack方式读取
    str = (void *)go_get_argument_by_stack(ctx, 2);
    len_ptr = (void *)go_get_argument_by_stack(ctx, 3);
    bpf_probe_read_kernel(&len, sizeof(len), (void *)&len_ptr);

    // Read函数的返回值第一个是int类型，存放在栈里的顺序是5
    ret_len_ptr = (void *)go_get_argument_by_stack(ctx, 5);
    bpf_probe_read_kernel(&ret_len, sizeof(ret_len), (void *)&ret_len_ptr);
    if (len == 0) {
        return 0;
    }

    struct go_tls_event *event = get_gotls_event();
    if (!event) {
        return 0;
    }

    debug_bpf_printk("gotls_read event, str addr:%p, len:%d\n", len_ptr, len);
    debug_bpf_printk("gotls_read event, str ret_len_ptr:%d, ret_len:%d\n",
                     ret_len_ptr, ret_len);
    event->data_len = len;
    event->event_type = GOTLS_EVENT_TYPE_READ;
    int ret =
        bpf_probe_read_user(&event->data, sizeof(event->data), (void *)str);
    if (ret < 0) {
        debug_bpf_printk(
            "gotls_text bpf_probe_read_user_str failed, ret:%d, str:%d\n", ret,
            str);
        return 0;
    }
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                          sizeof(struct go_tls_event));
    return 0;
}

// capture golang tls plaintext, supported golang stack-based ABI (go version
// < 1.17) func (c *Conn) Read(b []byte) (int, error)

SEC("uprobe/gotls_read_register")
int gotls_read_register(struct pt_regs *ctx) { return gotls_read(ctx, true); }

SEC("uprobe/gotls_read_stack")
int gotls_read_stack(struct pt_regs *ctx) { return gotls_read(ctx, false); }

/*
 * crypto/tls/common.go
 * func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error
 */
static __always_inline int gotls_mastersecret(struct pt_regs *ctx,
                                              bool is_register_abi) {
    //    const char *label, *clientrandom, *secret;
    void *lab_ptr, *cr_ptr, *secret_ptr;
    void *lab_len_ptr, *cr_len_ptr, *secret_len_ptr;
    s32 lab_len, cr_len, secret_len;

    /*
     *
     * in golang struct, slice header like this
     * type slice struct {
     * 	array unsafe.Pointer
     * 	len   int
     * 	cap   int
     * }
     * so, arument index are in the order one by one
     *
     */
    lab_ptr = (void *)go_get_argument(ctx, is_register_abi, 2);
    lab_len_ptr = (void *)go_get_argument(ctx, is_register_abi, 3);
    cr_ptr = (void *)go_get_argument(ctx, is_register_abi, 4);
    cr_len_ptr = (void *)go_get_argument(ctx, is_register_abi, 5);
    secret_ptr = (void *)go_get_argument(ctx, is_register_abi, 7);
    secret_len_ptr = (void *)go_get_argument(ctx, is_register_abi, 8);

    bpf_probe_read_kernel(&lab_len, sizeof(lab_len), (void *)&lab_len_ptr);
    bpf_probe_read_kernel(&cr_len, sizeof(lab_len), (void *)&cr_len_ptr);
    bpf_probe_read_kernel(&secret_len, sizeof(lab_len),
                          (void *)&secret_len_ptr);

    if (lab_len <= 0 || cr_len <= 0 || secret_len <= 0) {
        return 0;
    }

    debug_bpf_printk(
        "gotls_mastersecret read params length success, lab_len:%d, cr_len:%d, "
        "secret_len:%d\n",
        lab_len, cr_len, secret_len);

    struct mastersecret_gotls_t mastersecret_gotls = {};
    mastersecret_gotls.labellen = lab_len;
    mastersecret_gotls.client_random_len = cr_len;
    mastersecret_gotls.secret_len = secret_len;
    int ret = bpf_probe_read_user_str(&mastersecret_gotls.label,
                                      sizeof(mastersecret_gotls.label),
                                      (void *)lab_ptr);
    if (ret < 0) {
        debug_bpf_printk(
            "gotls_mastersecret read mastersecret label failed, ret:%d, "
            "lab_ptr:%p\n",
            ret, lab_ptr);
        return 0;
    }

    debug_bpf_printk("gotls_mastersecret read mastersecret label%s\n",
                     mastersecret_gotls.label);
    ret = bpf_probe_read_user_str(&mastersecret_gotls.client_random,
                                  sizeof(mastersecret_gotls.client_random),
                                  (void *)cr_ptr);
    if (ret < 0) {
        debug_bpf_printk(
            "gotls_mastersecret read mastersecret client_random failed, "
            "ret:%d, cr_ptr:%p\n",
            ret, cr_ptr);
        return 0;
    }

    ret = bpf_probe_read_user_str(&mastersecret_gotls.secret_,
                                  sizeof(mastersecret_gotls.secret_),
                                  (void *)secret_ptr);
    if (ret < 0) {
        debug_bpf_printk(
            "gotls_mastersecret read mastersecret secret_ failed, ret:%d, "
            "secret_ptr:%p\n",
            ret, secret_ptr);
        return 0;
    }

    bpf_perf_event_output(ctx, &mastersecret_go_events, BPF_F_CURRENT_CPU,
                          &mastersecret_gotls,
                          sizeof(struct mastersecret_gotls_t));
    return 0;
}

SEC("uprobe/gotls_mastersecret_register")
int gotls_mastersecret_register(struct pt_regs *ctx) {
    return gotls_mastersecret(ctx, true);
}

SEC("uprobe/gotls_mastersecret_stack")
int gotls_mastersecret_stack(struct pt_regs *ctx) {
    return gotls_mastersecret(ctx, false);
}
