#ifndef NOCORE
//CO:RE is enabled
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"

#else
#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#endif