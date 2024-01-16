#include "types.h"
#include "common/arguments.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filtering.h"

#include "utils.h"

SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    u32 parent_ns_pid = get_task_ns_pid(parent);
    u32 parent_ns_tgid = get_task_ns_tgid(parent);
    u32 child_ns_pid = get_task_ns_pid(child);
    u32 child_ns_tgid = get_task_ns_tgid(child);

    u32* pid = bpf_map_lookup_elem(&child_parent_map, &parent_ns_pid);
    if (unlikely(pid == NULL)) return 0;

    if (*pid == parent_ns_pid){
        ret = bpf_map_update_elem(&child_parent_map, &child_ns_pid, &parent_ns_pid, BPF_ANY);
    } else {
        bpf_printk("[stack] parent pid from map:%d\n", *pid);
    }
    return 0;
}

static __always_inline u32 probe_stack_warp(struct pt_regs* ctx, u32 point_key) {
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;
    point_args_t* point_args = bpf_map_lookup_elem(&uprobe_point_args, &point_key);
    if (unlikely(point_args == NULL)) return 0;

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (unlikely(filter == NULL)) return 0;

    save_to_submit_buf(p.event, (void *) &point_key, sizeof(u32), 0);
    u64 lr = 0;
    if(filter->is_32bit) {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[14]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    else {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[30]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    u64 sp = 0;
    bpf_probe_read_kernel(&sp, sizeof(sp), &ctx->sp);
    save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 2);
    u64 pc = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &ctx->pc);
    save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 3);

    int ctx_index = 0;
    op_ctx_t* op_ctx = bpf_map_lookup_elem(&op_ctx_map, &ctx_index);
    if (unlikely(op_ctx == NULL)) return 0;
    __builtin_memset((void *)op_ctx, 0, sizeof(op_ctx));

    op_ctx->reg_0 = READ_KERN(ctx->regs[0]);
    op_ctx->save_index = 4;
    op_ctx->op_key_index = 0;

    read_args(&p, point_args, op_ctx, ctx);

    if (op_ctx->skip_flag) {
        op_ctx->skip_flag = 0;
        return 0;
    }

    events_perf_submit(&p, UPROBE_ENTER);
    if (filter->signal > 0) {
        bpf_send_signal(filter->signal);
    }
    if (filter->tsignal > 0) {
        bpf_send_signal_thread(filter->tsignal);
    }
    return 0;
}

SEC("uprobe/stack_0")
int probe_stack_0(struct pt_regs* ctx) {
    u32 point_key = 0;
    return probe_stack_warp(ctx, point_key);
}

#define PROBE_STACK(name)                          \
    SEC("uprobe/stack_##name")                     \
    int probe_stack_##name(struct pt_regs* ctx)    \
    {                                              \
        u32 point_key = name;                       \
        return probe_stack_warp(ctx, point_key);    \
    }

// PROBE_STACK(0);
PROBE_STACK(1);
PROBE_STACK(2);
PROBE_STACK(3);
PROBE_STACK(4);
PROBE_STACK(5);
// PROBE_STACK(6);
// PROBE_STACK(7);
// PROBE_STACK(8);
// PROBE_STACK(9);
// PROBE_STACK(10);
// PROBE_STACK(11);
// PROBE_STACK(12);
// PROBE_STACK(13);
// PROBE_STACK(14);
// PROBE_STACK(15);
// PROBE_STACK(16);
// PROBE_STACK(17);
// PROBE_STACK(18);
// PROBE_STACK(19);