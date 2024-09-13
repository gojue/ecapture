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
    u32 src_ip6[4];
    u32 dst_ip6[4];
};

struct net_ctx_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
//    u8 cmdline[PATH_MAX_LEN];
};

////////////////////// ebpf maps //////////////////////
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 10240);
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

// filter_pcap_ebpf_l2 is a stub to inject pcap-filter.
static __noinline bool filter_pcap_ebpf_l2(void *_skb, void *__skb,
                                           void *___skb, void *data,
                                           void* data_end) {
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool filter_pcap_l2(struct __sk_buff *skb, void *data,
                                           void *data_end) {
    return filter_pcap_ebpf_l2((void *) skb, (void *) skb, (void *) skb, data,
                               data_end);
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

    struct net_id_t conn_id = {0};
    struct net_ctx_t *net_ctx = NULL;
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        // IPv6 packect
        uint32_t l6_hdr_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if (!skb_revalidate_data(skb, &data_start, &data_end, l6_hdr_off)) {
            return TC_ACT_OK;
        }

        struct ipv6hdr *iph = (struct ipv6hdr *)(data_start + sizeof(struct ethhdr));
        if (iph->nexthdr != IPPROTO_TCP && iph->nexthdr != IPPROTO_UDP) {
            return TC_ACT_OK;
        }

        conn_id.protocol = iph->nexthdr;
        __builtin_memcpy(conn_id.src_ip6, &iph->saddr, sizeof(iph->saddr));
        __builtin_memcpy(conn_id.dst_ip6, &iph->daddr, sizeof(iph->daddr));

        if (!skb_revalidate_data(skb, &data_start, &data_end,
                                 l6_hdr_off + sizeof(struct tcphdr))) {
            return TC_ACT_OK;
        }
        // udphdr
        // struct udphdr {
        //  __be16	source;
        //  __be16	dest;
        //  __be16	len;
        //  __sum16	check;
        // };
        // udp protocol reuse tcphdr
        struct tcphdr *hdr = (struct tcphdr *)(data_start + l6_hdr_off);

#ifndef KERNEL_LESS_5_2
    if (!filter_pcap_l2(skb, data_start, data_end))
        return TC_ACT_OK;
#endif

        conn_id.src_port = bpf_ntohs(hdr->source);
        conn_id.dst_port = bpf_ntohs(hdr->dest);

        net_ctx = bpf_map_lookup_elem(&network_map, &conn_id);
        if (net_ctx == NULL) {
            u32 tmp_ip[4];
            __builtin_memcpy(tmp_ip, conn_id.src_ip6, sizeof(conn_id.src_ip6));
            __builtin_memcpy(conn_id.src_ip6, conn_id.dst_ip6, sizeof(conn_id.dst_ip6));
            __builtin_memcpy(conn_id.dst_ip6, tmp_ip, sizeof(tmp_ip));
            u32 tmp_port = conn_id.src_port;
            conn_id.src_port = conn_id.dst_port;
            conn_id.dst_port = tmp_port;
            net_ctx = bpf_map_lookup_elem(&network_map, &conn_id);
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // IPv4 packect
        l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (!skb_revalidate_data(skb, &data_start, &data_end, l4_hdr_off)) {
            return TC_ACT_OK;
        }
        // IP headers
        struct iphdr *iph = (struct iphdr *)(data_start + sizeof(struct ethhdr));
        // filter out non-TCP packets
        if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }

        conn_id.protocol = iph->protocol;
        conn_id.src_ip4 = iph->saddr;
        conn_id.dst_ip4 = iph->daddr;
        if (!skb_revalidate_data(skb, &data_start, &data_end,
                                 l4_hdr_off + sizeof(struct tcphdr))) {
            return TC_ACT_OK;
        }
        // debug_bpf_printk("!!!capture_packets src_ip4 : %d, dst_ip4 port :%d\n", conn_id.src_ip4, conn_id.dst_ip4);
        // udp protocol reuse tcphdr
        struct tcphdr *hdr = (struct tcphdr *)(data_start + l4_hdr_off);

#ifndef KERNEL_LESS_5_2
    if (!filter_pcap_l2(skb, data_start, data_end))
        return TC_ACT_OK;
#endif

        conn_id.src_port = bpf_ntohs(hdr->source);
        conn_id.dst_port = bpf_ntohs(hdr->dest);
        // debug_bpf_printk("!!!capture_packets port : %d, dest port :%d\n", conn_id.src_port, conn_id.dst_port);
        net_ctx = bpf_map_lookup_elem(&network_map, &conn_id);
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
    }

    // new packet event
    struct skb_data_event_t event = {0};

    if (net_ctx != NULL) {
        // pid uid filter
#ifndef KERNEL_LESS_5_2
        if (target_pid != 0 && target_pid != net_ctx->pid) {
            return TC_ACT_OK;
        }
        if (target_uid != 0 && target_uid != net_ctx->uid) {
            return TC_ACT_OK;
        }
#endif
        event.pid = net_ctx->pid;
        __builtin_memcpy(event.comm, net_ctx->comm, TASK_COMM_LEN);
        debug_bpf_printk("capture packet process found, pid: %d, comm :%s\n", event.pid, event.comm);
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
SEC("classifier")
int egress_cls_func(struct __sk_buff *skb) {
    return capture_packets(skb, false);
};

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier")
int ingress_cls_func(struct __sk_buff *skb) {
    return capture_packets(skb, true);
};

SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg(struct pt_regs *ctx){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;
// 这里需要对所有的进程进行监控，所以不需要对pid和uid进行过滤，否则在TC capture_packets函数里无法使用pid\uid过滤网络包
//#ifndef KERNEL_LESS_5_2
//  if (target_pid != 0 && target_pid != pid) {
//      return 0;
//  }
//  if (target_uid != 0 && target_uid != uid) {
//      return 0;
//  }
//#endif
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL) {
        return 0;
    }

    u16 family, lport, dport;
    struct net_id_t conn_id = {0};
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family == AF_INET6) {
        u32 src_ip6[4], dst_ip6[4];
        bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        bpf_probe_read(&src_ip6, sizeof(src_ip6), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read(&dst_ip6, sizeof(dst_ip6), &sk->__sk_common.skc_v6_daddr);

        conn_id.protocol = IPPROTO_TCP;
        conn_id.src_port = lport;
        conn_id.dst_port = bpf_ntohs(dport);
        __builtin_memcpy(conn_id.src_ip6, src_ip6, sizeof(src_ip6));
        __builtin_memcpy(conn_id.dst_ip6, dst_ip6, sizeof(dst_ip6));
    } else if (family == AF_INET) {
        u32 src_ip4, dst_ip4;
        bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        bpf_probe_read(&src_ip4, sizeof(src_ip4), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&dst_ip4, sizeof(dst_ip4), &sk->__sk_common.skc_daddr);

        conn_id.protocol = IPPROTO_TCP;
        conn_id.src_port = lport;
        conn_id.src_ip4 = src_ip4;
        conn_id.dst_port = bpf_ntohs(dport);
        conn_id.dst_ip4 = dst_ip4;
    }

    struct net_ctx_t net_ctx;
    net_ctx.pid = pid;
    net_ctx.uid = uid;
    bpf_get_current_comm(&net_ctx.comm, sizeof(net_ctx.comm));

    debug_bpf_printk("tcp_sendmsg pid : %d, comm :%s\n", net_ctx.pid, net_ctx.comm);
    bpf_map_update_elem(&network_map, &conn_id, &net_ctx, BPF_ANY);
    return 0;
};

SEC("kprobe/udp_sendmsg")
int udp_sendmsg(struct pt_regs *ctx){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL) {
        return 0;
    }

    u16 family, lport, dport;
    struct net_id_t conn_id = {0};
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family == AF_INET6) {
        u32 src_ip6[4], dst_ip6[4];
        bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        bpf_probe_read(&src_ip6, sizeof(src_ip6), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read(&dst_ip6, sizeof(dst_ip6), &sk->__sk_common.skc_v6_daddr);

        conn_id.protocol = IPPROTO_UDP;
        conn_id.src_port = lport;
        conn_id.dst_port = bpf_ntohs(dport);
        __builtin_memcpy(conn_id.src_ip6, src_ip6, sizeof(src_ip6));
        __builtin_memcpy(conn_id.dst_ip6, dst_ip6, sizeof(dst_ip6));
    } else if (family == AF_INET) {
        u32 src_ip4, dst_ip4;
        bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        bpf_probe_read(&src_ip4, sizeof(src_ip4), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&dst_ip4, sizeof(dst_ip4), &sk->__sk_common.skc_daddr);

        conn_id.protocol = IPPROTO_UDP;
        conn_id.src_port = lport;
        conn_id.src_ip4 = src_ip4;
        conn_id.dst_port = bpf_ntohs(dport);
        conn_id.dst_ip4 = dst_ip4;
    }

    struct net_ctx_t net_ctx;
    net_ctx.pid = pid;
    net_ctx.uid = uid;
    bpf_get_current_comm(&net_ctx.comm, sizeof(net_ctx.comm));

    debug_bpf_printk("udp_sendmsg pid: %d, comm: %s\n", net_ctx.pid, net_ctx.comm);
    bpf_map_update_elem(&network_map, &conn_id, &net_ctx, BPF_ANY);
    return 0;
};
