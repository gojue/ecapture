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
struct skb_data_event_t {
    uint64_t ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 len;
    u32 ifindex;
};

struct net_id_t {
    u32 protocol;
    u32 src_port;
    u32 src_ip4;
//    u32 dst_port;
//    u32 dst_ip4;
//    u32 src_ip6[4];
//    u32 dst_ip6[4];
};

struct net_ctx_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
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

/*
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u16);   // key即为TCP连接的 本地port
    __type(value, u32); // pid
    __uint(max_entries, 10240);
} pid_port SEC(".maps");
*/

////////////////////// General helper functions //////////////////////
static __inline struct skb_data_event_t *make_skb_data_event() {
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
int capture_packets(struct __sk_buff *skb, bool is_ingress) {
    // packet data
    unsigned char *data_start = (void *)(long)skb->data;
    unsigned char *data_end = (void *)(long)skb->data_end;
    u32 data_len = (u32)skb->len;
    uint32_t l4_hdr_off;

    // Ethernet headers
    struct ethhdr *eth = (struct ethhdr *)data_start;
    // IP headers
    struct iphdr *iph = (struct iphdr *)(data_start + sizeof(struct ethhdr));

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

    // filter out non-TCP packets
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }
    if (!skb_revalidate_data(skb, &data_start, &data_end,
                             l4_hdr_off + sizeof(struct tcphdr))) {
        return TC_ACT_OK;
    }
    struct tcphdr *tcp = (struct tcphdr *)(data_start + l4_hdr_off);

#ifndef KERNEL_LESS_5_2
    if (tcp->source != bpf_htons(target_port) &&
        tcp->dest != bpf_htons(target_port)) {
        return TC_ACT_OK;
    }
#endif
    debug_bpf_printk("capture_packets port : %d, dest port :%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
/*
    // get the skb data event
    struct net_id_t conn_id = {0};
    conn_id.protocol = iph->protocol;
    conn_id.src_ip4 = iph->saddr;
    conn_id.src_port = tcp->source;

    struct net_ctx_t *net_ctx = bpf_map_lookup_elem(&network_map, &conn_id);
    if (net_ctx == NULL) {
        // exchange src and dst
        conn_id.src_ip4 = iph->daddr;
        conn_id.src_port = tcp->dest;
        net_ctx = bpf_map_lookup_elem(&network_map, &conn_id);
    }
*/
    // new packet event
    struct skb_data_event_t event = {0};
//    if (net_ctx != NULL) {
//        event.pid = net_ctx->pid;
//        bpf_probe_read(&event.comm, sizeof(event.comm), net_ctx->comm);
//    }
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

/*
struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	*/
static __always_inline int get_process(struct bpf_sock_addr *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
// 仅对指定PID的进程发起的connect事件进行捕获
#ifndef KERNEL_LESS_5_2
    if (target_pid != 0 && target_pid != pid) {
        return SOCKET_ALLOW;
    }
#endif
    if (ctx->protocol != IPPROTO_TCP) {
        return SOCKET_ALLOW;
    }
    u32 port = bpf_ntohs(ctx->user_port);
    if (port == 0) {
        return SOCKET_ALLOW;
    }
    if (ctx->family != AF_INET ) {
        debug_bpf_printk("[eCapture] unsupported family %d\n",  ctx->family);
        return SOCKET_ALLOW;
    }

    // 从 ctx->sk中获取五元组
    struct net_id_t conn_id = {0};
//    conn_id.src_ip4 = bpf_ntohs(ctx->msg_src_ip4);
    bpf_probe_read(&conn_id.src_ip4, sizeof(conn_id.src_ip4), &ctx->msg_src_ip4);
    conn_id.protocol = ctx->sk->protocol;
    conn_id.src_port = bpf_ntohs(ctx->sk->src_port);

    struct net_ctx_t net_ctx;
    net_ctx.pid = pid;
    bpf_get_current_comm(&net_ctx.comm, sizeof(net_ctx.comm));
    debug_bpf_printk("[!!!!!] conn_id user_ip4:%d, msg_src_ip4:%d, protocol:%d\n",  bpf_ntohl(ctx->user_ip4), bpf_ntohl(conn_id.src_ip4), conn_id.protocol);
    debug_bpf_printk("[!!!!!] wrote network_map map: user_port %d ==> pid:%d, comm:%s\n",  port, pid, net_ctx.comm);
    bpf_map_update_elem(&network_map, &conn_id, &net_ctx, BPF_ANY);
    return SOCKET_ALLOW;
}


// tracee used kprobe/security_socket_bind.
SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx) {
    if (ctx->user_family != AF_INET || ctx->family != AF_INET) {
        return SOCKET_ALLOW;
    }
    return get_process(ctx);
}

/*
SEC("cgroup/connect6")
int cg_connect6(struct bpf_sock_addr *ctx) {
    if (ctx->user_family != AF_INET || ctx->family != AF_INET) {
        return SOCKET_ALLOW;
    }
    return get_process(ctx);
}
*/