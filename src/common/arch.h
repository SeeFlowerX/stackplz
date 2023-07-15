#ifndef __STACKPLZ_ARCH_H__
#define __STACKPLZ_ARCH_H__

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "common/common.h"

#if defined(__TARGET_ARCH_x86)
    #define PT_REGS_PARM6(ctx) ((ctx)->r9)
#elif defined(__TARGET_ARCH_arm64)
    #define PT_REGS_PARM6(x) ((x)->regs[5])
#endif

#endif