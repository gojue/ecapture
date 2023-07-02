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

#define TC_PACKET_MIN_SIZE 36
#define SOCKET_ALLOW 1
#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);               \
        _val;                                                           \
    })

struct skb_data_event_t {
    uint64_t ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
//    u8 cmdline[PATH_MAX_LEN];
    u32 len;
    u32 ifindex;
};

struct net_id_t {
    u32 protocol;
    u32 src_port;
    u32 src_ip4;
    u32 dst_port;
    u32 dst_ip4;
//    u32 src_ip6[4];
//    u32 dst_ip6[4];
};

struct net_ctx_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
//    u8 cmdline[PATH_MAX_LEN];
};

////////////////////// ebpf maps //////////////////////
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} skb_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct skb_data_event_t);
    __uint(max_entries, 1);
} skb_data_buffer_heap SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct net_id_t);
    __type(value, struct net_ctx_t);
    __uint(max_entries, 10240);
} network_map SEC(".maps");

////////////////////// General helper functions //////////////////////

static __always_inline void get_proc_cmdline(struct task_struct *task, char *cmdline, int size)
{
    struct mm_struct *mm = READ_KERN(task->mm);
    long unsigned int args_start = READ_KERN(mm->arg_start);
    long unsigned int args_end = READ_KERN(mm->arg_end);
    int len = (args_end - args_start);
    if (len >= size)
        len = size - 1;
    bpf_probe_read(cmdline, len & (size - 1), (const void *)args_start);
}

static __always_inline struct skb_data_event_t *make_skb_data_event() {
    u32 kZero = 0;
    struct skb_data_event_t *event =
        bpf_map_lookup_elem(&skb_data_buffer_heap, &kZero);
    if (event == NULL) {
        return NULL;
    }
    return event;
}

static __always_inline bool skb_revalidate_data(struct __sk_buff *skb,
                                                uint8_t **head, uint8_t **tail,
                                                const u32 offset) {
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }

        *head = (uint8_t *)(long)skb->data;
        *tail = (uint8_t *)(long)skb->data_end;

        if (*head + offset > *tail) {
            return false;
        }
    }

    return true;
}

///////////////////// ebpf functions //////////////////////
static __always_inline int capture_packets(struct __sk_buff *skb, bool is_ingress) {
    // packet data
    unsigned char *data_start = (void *)(long)skb->data;
    unsigned char *data_end = (void *)(long)skb->data_end;
    if (data_start + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }

    u32 data_len = (u32)skb->len;
    uint32_t l4_hdr_off;

    // Ethernet headers
    struct ethhdr *eth = (struct ethhdr *)data_start;


    // Simple length check
    if ((data_start + sizeof(struct ethhdr) + sizeof(struct iphdr)) >
        data_end) {
        return TC_ACT_OK;
    }

    // filter out non-IP packets
    // TODO support IPv6
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (!skb_revalidate_data(skb, &data_start, &data_end, l4_hdr_off)) {
        return TC_ACT_OK;
    }

    // IP headers
    struct iphdr *iph = (struct iphdr *)(data_start + sizeof(struct ethhdr));
    // filter out non-TCP packets
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }
    struct net_id_t conn_id = {0};
    conn_id.protocol = iph->protocol;
    conn_id.src_ip4 = iph->saddr;
    conn_id.dst_ip4 = iph->daddr;

    if (!skb_revalidate_data(skb, &data_start, &data_end,
                             l4_hdr_off + sizeof(struct tcphdr))) {
        return TC_ACT_OK;
    }
//    debug_bpf_printk("!!!capture_packets src_ip4 : %d, dst_ip4 port :%d\n", conn_id.src_ip4, conn_id.dst_ip4);
    struct tcphdr *tcp = (struct tcphdr *)(data_start + l4_hdr_off);

#ifndef KERNEL_LESS_5_2
    if (tcp->source != bpf_htons(target_port) &&
        tcp->dest != bpf_htons(target_port)) {
        return TC_ACT_OK;
    }
#endif


    conn_id.src_port = bpf_ntohs(tcp->source);
    conn_id.dst_port = bpf_ntohs(tcp->dest);
//    debug_bpf_printk("!!!capture_packets port : %d, dest port :%d\n", conn_id.src_port, conn_id.dst_port);

    struct net_ctx_t *net_ctx = bpf_map_lookup_elem(&network_map, &conn_id);
    if (net_ctx == NULL) {
        // exchange src and dst
        u32 tmp_ip = conn_id.src_ip4;
        conn_id.src_ip4 = conn_id.dst_ip4;
        conn_id.dst_ip4 = tmp_ip;
        u32 tmp_port = conn_id.src_port;
        conn_id.src_port = conn_id.dst_port;
        conn_id.dst_port = tmp_port;
        net_ctx = bpf_map_lookup_elem(&network_map, &conn_id);
    }

    // new packet event
    struct skb_data_event_t event = {0};
//    struct skb_data_event_t *event = make_skb_data_event();
//    if (event == NULL) {
//        return TC_ACT_OK;
//    }
    if (net_ctx != NULL) {
        event.pid = net_ctx->pid;
        __builtin_memcpy(event.comm, net_ctx->comm, TASK_COMM_LEN);
//        __builtin_memcpy(event.cmdline, net_ctx->cmdline, PATH_MAX_LEN);
        debug_bpf_printk("capture packet process found, pid: %d, comm :%s\n", event.pid, event.comm);
    } else {
        debug_bpf_printk("capture packet process not found, src_port:%d, dst_port:%d\n", conn_id.src_port, conn_id.dst_port);
    }
    event.ts = bpf_ktime_get_ns();
    event.len = skb->len;
    event.ifindex = skb->ifindex;

    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64)skb->len << 32;

    // via aquasecurity/tracee    tracee.bpf.c tc_probe
    // if net_packet event not chosen, send minimal data only:
    //     timestamp (u64)      8 bytes
    //     pid (u32)            4 bytes
    //     comm (char[])       16 bytes
    //     packet len (u32)     4 bytes
    //     ifindex (u32)        4 bytes
    size_t pkt_size = TC_PACKET_MIN_SIZE;
    bpf_perf_event_output(skb, &skb_events, flags, &event, pkt_size);

    //    debug_bpf_printk("new packet captured on egress/ingress (TC),
    //    length:%d\n", data_len);
    return TC_ACT_OK;
}

// egress_cls_func is called for packets that are going out of the network
SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb) {
    return capture_packets(skb, false);
};

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb) {
    return capture_packets(skb, true);
};

SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg(struct pt_regs *ctx){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
// 仅对指定PID的进程发起的connect事件进行捕获
#ifndef KERNEL_LESS_5_2
  if (target_pid != 0 && target_pid != pid) {
      return 0;
  }
#endif
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL) {
        return 0;
    }

    u16 family, lport, dport;
    u32 src_ip4, dst_ip4;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family != AF_INET) {
        return 0;
    }
    bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read(&src_ip4, sizeof(src_ip4), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&dst_ip4, sizeof(dst_ip4), &sk->__sk_common.skc_daddr);

    struct net_id_t conn_id = {0};
    conn_id.protocol = IPPROTO_TCP;
    conn_id.src_port = lport;
    conn_id.src_ip4 = src_ip4;
    conn_id.dst_port = bpf_ntohs(dport);
    conn_id.dst_ip4 = dst_ip4;

    struct net_ctx_t net_ctx;
    net_ctx.pid = pid;
    bpf_get_current_comm(&net_ctx.comm, sizeof(net_ctx.comm));
    //
//    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//    get_proc_cmdline(task, net_ctx.cmdline, sizeof(net_ctx.cmdline));
//
    debug_bpf_printk("tcp_sendmsg pid : %d, comm :%s\n", net_ctx.pid, net_ctx.comm);
    bpf_map_update_elem(&network_map, &conn_id, &net_ctx, BPF_ANY);
    return 0;
};