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

#ifndef ECAPTURE_GOTLS_H
#define ECAPTURE_GOTLS_H

// true: 1.5 or older
// false: newer
//volatile const bool is_register_abi;

// golang register-based ABI via https://tip.golang.org/src/cmd/compile/abi-internal
#ifndef NOCORE

#if defined(__TARGET_ARCH_x86)
#define GO_PARAM1(x) BPF_CORE_READ((x), ax)
#define GO_PARAM2(x) BPF_CORE_READ((x), bx)
#define GO_PARAM3(x) BPF_CORE_READ((x), cx)
#define GO_PARAM4(x) BPF_CORE_READ((x), di)
#define GO_PARAM5(x) BPF_CORE_READ((x), si)
#define GO_PARAM6(x) BPF_CORE_READ((x), r8)
#define GO_PARAM7(x) BPF_CORE_READ((x), r9)
#define GO_PARAM8(x) BPF_CORE_READ((x), r10)
#define GO_PARAM9(x) BPF_CORE_READ((x), r11)
#define GOROUTINE(x) BPF_CORE_READ((x), r14)
#define GO_SP(x) BPF_CORE_READ((x), sp)
#elif defined(__TARGET_ARCH_arm64)
#define GO_PARAM1(x) PT_REGS_PARM1_CORE(x)
#define GO_PARAM2(x) PT_REGS_PARM2_CORE(x)
#define GO_PARAM3(x) PT_REGS_PARM3_CORE(x)
#define GO_PARAM4(x) PT_REGS_PARM4_CORE(x)
#define GO_PARAM5(x) PT_REGS_PARM5_CORE(x)
#define GO_PARAM6(x) BPF_CORE_READ(((PT_REGS_ARM64 *)(x)), regs[5])
#define GO_PARAM7(x) BPF_CORE_READ(((PT_REGS_ARM64 *)(x)), regs[6])
#define GO_PARAM8(x) BPF_CORE_READ(((PT_REGS_ARM64 *)(x)), regs[7])
#define GO_PARAM9(x) BPF_CORE_READ(((PT_REGS_ARM64 *)(x)), regs[8])
#define GOROUTINE(x) BPF_CORE_READ(((PT_REGS_ARM64 *)(x)), regs[28])
#define GO_SP(x) PT_REGS_SP_CORE(x)
#endif

#else

#if defined(__x86_64__)
#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GO_PARAM4(x) ((x)->di)
#define GO_PARAM5(x) ((x)->si)
#define GO_PARAM6(x) ((x)->r8)
#define GO_PARAM7(x) ((x)->r9)
#define GO_PARAM8(x) ((x)->r10)
#define GO_PARAM9(x) ((x)->r11)
#define GOROUTINE(x) ((x)->r14)
#define GO_SP(x) ((x)->sp)
#elif defined(__aarch64__)
#define GO_PARAM1(x) PT_REGS_PARM1(x)
#define GO_PARAM2(x) PT_REGS_PARM2(x)
#define GO_PARAM3(x) PT_REGS_PARM3(x)
#define GO_PARAM4(x) PT_REGS_PARM4(x)
#define GO_PARAM5(x) (((PT_REGS_ARM64 *)(x))->regs[4])
#define GO_PARAM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#define GO_PARAM7(x) (((PT_REGS_ARM64 *)(x))->regs[6])
#define GO_PARAM8(x) (((PT_REGS_ARM64 *)(x))->regs[7])
#define GO_PARAM9(x) (((PT_REGS_ARM64 *)(x))->regs[8])
#define GOROUTINE(x) (((PT_REGS_ARM64 *)(x))->regs[28])
#define GO_SP(x) PT_REGS_SP(x)
#endif

#endif

void* go_get_argument_by_reg(struct pt_regs *ctx, int index) {
    switch (index) {
        case 1:
            return (void*)GO_PARAM1(ctx);
        case 2:
            return (void*)GO_PARAM2(ctx);
        case 3:
            return (void*)GO_PARAM3(ctx);
        case 4:
            return (void*)GO_PARAM4(ctx);
        case 5:
            return (void*)GO_PARAM5(ctx);
        case 6:
            return (void*)GO_PARAM6(ctx);
        case 7:
            return (void*)GO_PARAM7(ctx);
        case 8:
            return (void*)GO_PARAM8(ctx);
        case 9:
            return (void*)GO_PARAM9(ctx);
        default:
            return NULL;
    }
}

void* go_get_argument_by_stack(struct pt_regs *ctx, int index) {
    void* ptr = 0;
    bpf_probe_read(&ptr, sizeof(ptr), (void *)(PT_REGS_SP(ctx)+(index*8)));
    return ptr;
}

void* go_get_argument(struct pt_regs *ctx,bool is_register_abi, int index) {
    if (is_register_abi) {
        return go_get_argument_by_reg(ctx, index);
    }
    return go_get_argument_by_stack(ctx, index);
}

#endif