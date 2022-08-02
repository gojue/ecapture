
struct skb_data_event_t {
    u32 data_len;
    char data[SKB_MAX_DATA_SIZE];
};

typedef struct net_id {
    struct in6_addr address;
    u16 port;
    u16 protocol;
} net_id_t;

typedef struct net_ctx {
    u32 host_tid;
    char comm[TASK_COMM_LEN];
} net_ctx_t;

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

/*
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct net_id_t);
    __type(value, struct net_ctx_t);
    __uint(max_entries, 10240);
} network_map SEC(".maps");
*/

////////////////////// General helper functions //////////////////////
static __inline struct skb_data_event_t* make_skb_data_event() {
    u32 kZero = 0;
    struct skb_data_event_t* event =
        bpf_map_lookup_elem(&skb_data_buffer_heap, &kZero);
    if (event == NULL) {
        return NULL;
    }
    return event;
}

static __always_inline bool
skb_revalidate_data(struct __sk_buff *skb, uint8_t **head, uint8_t **tail, const u32 offset)
{
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }

        *head = (uint8_t *) (long) skb->data;
        *tail = (uint8_t *) (long) skb->data_end;

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
    if ((data_start + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end) {
        return TC_ACT_OK;
    }

    // filter out non-IP packets
    // TODO support IPv6
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (!skb_revalidate_data(skb, &data_start, &data_end, l4_hdr_off))
    {
        return TC_ACT_OK;
    }

    // filter out non-TCP packets
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }
    if (!skb_revalidate_data(skb, &data_start, &data_end, l4_hdr_off + sizeof(struct tcphdr)))
    {
        return TC_ACT_UNSPEC;
    }
    struct tcphdr *tcp = (struct tcphdr *) (data_start + l4_hdr_off);

    if (tcp->source != bpf_htons(443) && tcp->dest != bpf_htons(443)) {
        return TC_ACT_OK;
    }

    debug_bpf_printk("capture_packets port : %d, dest port :%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
    // get the skb data event
    net_id_t connect_id = {0};
    struct skb_data_event_t* event = make_skb_data_event();

    if (event == NULL) {
        return 0;
    }
    // make sure data_len is not negative
    event->data_len = data_len;

    bpf_probe_read_kernel(event->data, sizeof(event->data), &data_start);

    bpf_perf_event_output(skb, &skb_events, BPF_F_CURRENT_CPU, event,
                          sizeof(struct skb_data_event_t));
    debug_bpf_printk("new packet captured on egress/ingress (TC), length:%d\n", data_len);
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
    return TC_ACT_OK;
    return capture_packets(skb, true);
};