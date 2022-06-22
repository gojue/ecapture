/* Copyright © 2022 Hengqi Chen */
#include "ecapture.h"

struct go_ssl_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	int data_len;
	char comm[TASK_COMM_LEN];
	char data[MAX_DATA_SIZE_OPENSSL];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct go_ssl_event);
	__uint(max_entries, 1);
} heap SEC(".maps");

#ifndef NOCORE

#if defined(__TARGET_ARCH_x86)
#define GO_REG1(x) BPF_CORE_READ((x), ax)
#define GO_REG2(x) BPF_CORE_READ((x), bx)
#define GO_REG3(x) BPF_CORE_READ((x), cx)
#define GO_REG4(x) BPF_CORE_READ((x), di)
#define GO_SP(x)   BPF_CORE_READ((x), sp)
#elif defined(__TARGET_ARCH_arm64)
#define GO_REG1(x) PT_REGS_PARM1_CORE(x)
#define GO_REG2(x) PT_REGS_PARM2_CORE(x)
#define GO_REG3(x) PT_REGS_PARM3_CORE(x)
#define GO_REG4(x) PT_REGS_PARM4_CORE(x)
#define GO_SP(x)   PT_REGS_SP_CORE(x)
#endif

#else

#if defined(__x86_64__)
#define GO_REG1(x) ((x)->ax)
#define GO_REG2(x) ((x)->bx)
#define GO_REG3(x) ((x)->cx)
#define GO_REG4(x) ((x)->di)
#define GO_SP(x)   ((x)->sp)
#elif defined(__aarch64__)
#define GO_REG1(x) PT_REGS_PARM1(x)
#define GO_REG2(x) PT_REGS_PARM2(x)
#define GO_REG3(x) PT_REGS_PARM3(x)
#define GO_REG4(x) PT_REGS_PARM4(x)
#define GO_SP(x)   PT_REGS_SP(x)
#endif

#endif

static struct go_ssl_event *get_event()
{
	static const int zero = 0;
	struct go_ssl_event *event;
	__u64 id;

	event = bpf_map_lookup_elem(&heap, &zero);
	if (!event)
		return NULL;

	id = bpf_get_current_pid_tgid();
	event->ts_ns = bpf_ktime_get_ns();
	event->pid = id >> 32;
	event->tid = (__u32)id;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	return event;
}

SEC("uprobe/abi_stack")
int BPF_KPROBE(probe_stack)
{
	struct go_ssl_event *event;
	__u64 *sp = (void *)GO_SP(ctx), addr;
	int len, record_type;
	const char *str;

	bpf_probe_read_user(&record_type, sizeof(record_type), sp + 2);
	if (record_type != 23)
		return 0;

	bpf_probe_read_user(&addr, sizeof(addr), sp + 3);
	bpf_probe_read_user(&len, sizeof(len), sp + 4);

	event = get_event();
	if (!event)
		return 0;

	str = (void *)addr;
	bpf_probe_read_user_str(event->data, sizeof(event->data), str);
	event->data_len = len;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
	return 0;
}

SEC("uprobe/abi_register")
int BPF_KPROBE(probe_register)
{
	struct go_ssl_event *event;
	int len, record_type;
	const char *str;

	record_type = GO_REG2(ctx);
	str = (void *)GO_REG3(ctx);
	len = GO_REG4(ctx);

	if (record_type != 23)
		return 0;

	event = get_event();
	if (!event)
		return 0;

	bpf_probe_read_user_str(event->data, sizeof(event->data), str);
	event->data_len = len;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
	return 0;
}
