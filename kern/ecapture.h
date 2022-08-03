#ifndef ECAPTURE_H
#define ECAPTURE_H

#ifndef NOCORE
//CO:RE is enabled
#include "vmlinux.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"

#else
#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#endif

#include "common.h"

#endif
