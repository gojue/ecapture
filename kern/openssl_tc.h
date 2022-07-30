
struct skb_data_event_t {
    u32 data_len;
    char data[SKB_MAX_DATA_SIZE];
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

///////////////////// ebpf functions //////////////////////
int capture_packets(struct __sk_buff *skb) {

    // packet data
    unsigned char *data_start = (void *)(long)skb->data;
    unsigned char *data_end = (void *)(long)skb->data_end;
    u32 data_len = (u32)skb->len;

    if (data_len < 70) {
        return TC_ACT_OK;
    }
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

    // filter out non-TCP packets
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

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
   return capture_packets(skb);
};

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb) {
    return TC_ACT_OK;
    return capture_packets(skb);
};