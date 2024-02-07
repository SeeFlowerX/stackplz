#ifndef __STACKPLZ_EVENTS_ARGS_H__
#define __STACKPLZ_EVENTS_ARGS_H__

#include "bpf/bpf_helpers.h"
#include "common/arch.h"
#include "maps.h"

static __always_inline int save_regs(ctx_regs_t *ctx_regs, u32 event_id)
{
    u64 id = event_id;
    u32 tid = bpf_get_current_pid_tgid();
    id = id << 32 | tid;
    bpf_map_update_elem(&ctx_regs_map, &id, ctx_regs, BPF_ANY);
    return 0;
}

static __always_inline int load_regs(ctx_regs_t *ctx_regs, u32 event_id)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;
    ctx_regs_t *saved_ctx_regs = bpf_map_lookup_elem(&ctx_regs_map, &id);
    if (saved_ctx_regs == 0) {
        return -1;
    }
    for (int i = 0; i < 31; i++) {
        ctx_regs->regs[i] = saved_ctx_regs->regs[i];
    }
    ctx_regs->sp = saved_ctx_regs->sp;
    ctx_regs->pc = saved_ctx_regs->pc;
    ctx_regs->flag = saved_ctx_regs->flag;
    return 0;
}

static __always_inline int del_regs(u32 event_id)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 id = event_id;
    id = id << 32 | tid;
    bpf_map_delete_elem(&ctx_regs_map, &id);
    return 0;
}

#endif