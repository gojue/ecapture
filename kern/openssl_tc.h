
SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb)
{
    debug_bpf_printk("new packet captured on egress (TC)\n");
    return TC_ACT_OK;
};

SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb)
{
    debug_bpf_printk("new packet captured on ingress (TC)\n");
    return TC_ACT_OK;
};