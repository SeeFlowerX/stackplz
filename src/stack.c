#include "utils.h"
#include <stdbool.h>

#include "types.h"
#include "common/arguments.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filtering.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_WATCH_PROC_COUNT);
} watch_proc_map SEC(".maps");

typedef struct uprobe_point_args_t {
    u32 count;
    point_arg point_args[MAX_POINT_ARG_COUNT];
} uprobe_point_args;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct uprobe_point_args_t);
    __uint(max_entries, 512);
} uprobe_point_args_map SEC(".maps");


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
    if (pid == NULL) {
        return 0;
    }
    if (*pid == parent_ns_pid){
        ret = bpf_map_update_elem(&child_parent_map, &child_ns_pid, &parent_ns_pid, BPF_ANY);
    } else {
        bpf_printk("[stack] parent pid from map:%d\n", *pid);
    }

    return 0;
}

static __always_inline u32 probe_stack_warp(struct pt_regs* ctx, u32 args_key) {

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct uprobe_point_args_t* uprobe_point_args = bpf_map_lookup_elem(&uprobe_point_args_map, &args_key);
    if (uprobe_point_args == NULL) {
        return 0;
    }

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    save_to_submit_buf(p.event, (void *) &args_key, sizeof(u32), 0);
    u64 lr = 0;
    if(filter->is_32bit) {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[14]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    else {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[30]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    u64 pc = 0;
    u64 sp = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &ctx->pc);
    bpf_probe_read_kernel(&sp, sizeof(sp), &ctx->sp);
    save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 2);
    save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 3);

    u32 point_arg_count = MAX_POINT_ARG_COUNT;
    if (uprobe_point_args->count <= point_arg_count) {
        point_arg_count = uprobe_point_args->count;
    }

    int next_arg_index = 4;
    for (int i = 0; i < point_arg_count; i++) {
        struct point_arg_t* point_arg = (struct point_arg_t*) &uprobe_point_args->point_args[i];

        u64 arg_ptr = 0;
        if (point_arg->read_index == READ_INDEX_SKIP) {
            continue;
        }
        if (point_arg->read_index == READ_INDEX_REG) {
            // 未来可能允许读取很多个参数...
            if (i > REG_ARM64_LR) {
                continue;
            }
            arg_ptr = READ_KERN(ctx->regs[i]);
        } else if (point_arg->read_index == REG_ARM64_SP) {
            arg_ptr = READ_KERN(ctx->sp);
        } else if (point_arg->read_index == REG_ARM64_PC) {
            arg_ptr = READ_KERN(ctx->pc);
        } else if (point_arg->read_index <= REG_ARM64_LR) {
            arg_ptr = READ_KERN(ctx->regs[point_arg->read_index]);
        } else {
            continue;
        }

        // 先保存参数值本身
        save_to_submit_buf(p.event, (void *)&arg_ptr, sizeof(u64), next_arg_index);
        next_arg_index += 1;

        if (point_arg->read_flag != UPROBE_ENTER_READ) {
            continue;
        }
        if (arg_ptr == 0) {
            continue;
        }
        u32 read_count = MAX_BUF_READ_SIZE;
        if (point_arg->item_countindex != READ_INDEX_SKIP) {
            u32 item_count = 0;
            // 以寄存器值作为索引 只包含 x0-x28
            // x29 是fp寄存器 所以不包含在内
            if (point_arg->item_countindex < REG_ARM64_X29) {
                item_count = READ_KERN(ctx->regs[point_arg->item_countindex]);
            }
            if (item_count != 0 && item_count <= read_count) {
                read_count = item_count;
            }
        } else if (point_arg->size <= read_count) {
            read_count = point_arg->size;
        }
        next_arg_index = read_arg(p, point_arg, arg_ptr, read_count, next_arg_index);
    }
    events_perf_submit(&p, UPROBE_ENTER);
    if (filter->signal > 0) {
        bpf_send_signal(filter->signal);
    }
    return 0;
}

SEC("uprobe/stack_0")
int probe_stack_0(struct pt_regs* ctx) {
    u32 args_key = 0;
    return probe_stack_warp(ctx, args_key);
}

#define PROBE_STACK(name)                          \
    SEC("uprobe/stack_##name")                     \
    int probe_stack_##name(struct pt_regs* ctx)    \
    {                                              \
        u32 args_key = name;                       \
        return probe_stack_warp(ctx, args_key);    \
    }

// PROBE_STACK(0);
PROBE_STACK(1);
PROBE_STACK(2);
PROBE_STACK(3);
PROBE_STACK(4);
PROBE_STACK(5);
PROBE_STACK(6);
PROBE_STACK(7);
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