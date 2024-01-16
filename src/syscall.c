#include "utils.h"
#include <stdbool.h>

#include "types.h"
#include "common/arguments.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filtering.h"

SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    // 为了实现仅指定单个pid时 能追踪其产生的子进程的相关系统调用 设计如下
    // 维护一个 map
    // - 其 key 为进程 pid 
    // - 其 value 为其父进程 pid
    // 逻辑如下
    // 当进入此处后，先获取进程本身信息，然后通过自己的父进程 pid 去 map 中取出对应的value
    // 如果没有取到则说明这个进程不是要追踪的进程
    // 取到了，则说明这个是之前产生的进程，然后向map存入进程信息 key 就是进程本身 pid 而 value则是父进程pid
    // 那么最开始的 pid 从哪里来呢 答案是从首次通过 sys_enter 的过滤之后 向该map存放第一个key value
    // 1. child_parent_map => {}
    // 2. 出现第一个通过 sys_enter 处的过滤的进程，则更新map -> child_parent_map => {12345: 12345}
    // 3. sched_process_fork 获取进程的父进程信息，检查map，发现父进程存在其中，则更新map -> child_parent_map => {12345: 12345, 22222: 12345}
    // 4. sys_enter/sys_exit 有限次遍历 child_parent_map 取出key逐个比较当前进程的pid
    // 待实现...

    u32 parent_ns_pid = get_task_ns_pid(parent);
    u32 parent_ns_tgid = get_task_ns_tgid(parent);
    u32 child_ns_pid = get_task_ns_pid(child);
    u32 child_ns_tgid = get_task_ns_tgid(child);

    // bpf_printk("[syscall] parent_ns_pid:%d child_ns_pid:%d\n", parent_ns_pid, child_ns_pid);
    u32* pid = bpf_map_lookup_elem(&child_parent_map, &parent_ns_pid);
    if (unlikely(pid == NULL)) return 0;

    if (*pid == parent_ns_pid){
        // map中取出的父进程pid 这里fork产生子进程的pid相同
        // 说明这个进程是我们自己添加的
        // 那么现在把新产生的这个子进程 pid 放入 map
        ret = bpf_map_update_elem(&child_parent_map, &child_ns_pid, &parent_ns_pid, BPF_ANY);
        // bpf_printk("[syscall] parent_ns_pid:%d child_ns_pid:%d ret:%ld\n", parent_ns_pid, child_ns_pid, ret);
    } else {
        // 理论上不应该走到这个分支
        // 因为我们用当前函数这里的 parent 期望的就是其之前map中的
        bpf_printk("[syscall] parent pid from map:%d\n", *pid);
    }

    return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_syscalls_sys_enter(struct bpf_raw_tracepoint_args* ctx) {
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
    u64 syscallno = READ_KERN(regs->syscallno);
    u32 sysno = (u32)syscallno;
    // 先根据调用号确定有没有对应的参数获取方案 没有直接结束
    point_args_t* point_args = bpf_map_lookup_elem(&sysenter_point_args, &sysno);
    if (unlikely(point_args == NULL)) return 0;

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (unlikely(filter == NULL)) return 0;

    if (filter->trace_mode == TRACE_COMMON) {
        // 非 追踪全部syscall模式
        u32 sysno_whitelist_key = sysno + SYS_WHITELIST_START;
        u32 *sysno_whitelist_value = bpf_map_lookup_elem(&common_list, &sysno_whitelist_key);
        if (unlikely(sysno_whitelist_value == NULL)) return 0;
    }

    // 黑名单同样对 追踪全部syscall模式 有效
    u32 sysno_blacklist_key = sysno + SYS_BLACKLIST_START;
    u32 *sysno_blacklist_value = bpf_map_lookup_elem(&common_list, &sysno_blacklist_key);
    if (unlikely(sysno_blacklist_value != NULL)) return 0;

    // 保存寄存器应该放到所有过滤完成之后
    args_t saved_regs = {};
    saved_regs.args[0] = READ_KERN(regs->regs[0]);
    saved_regs.args[1] = READ_KERN(regs->regs[1]);
    saved_regs.args[2] = READ_KERN(regs->regs[2]);
    saved_regs.args[3] = READ_KERN(regs->regs[3]);
    saved_regs.args[4] = READ_KERN(regs->regs[4]);
    saved_regs.args[5] = READ_KERN(regs->regs[5]);
    save_args(&saved_regs, SYSCALL_ENTER);

    // event->context 已经有进程的信息了
    save_to_submit_buf(p.event, (void *) &sysno, sizeof(u32), 0);

    // 先获取 lr sp pc 并发送 这样可以尽早计算调用来源情况
    // READ_KERN 好像有问题
    u64 lr = 0;
    if(filter->is_32bit) {
        bpf_probe_read_kernel(&lr, sizeof(lr), &regs->regs[14]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    else {
        bpf_probe_read_kernel(&lr, sizeof(lr), &regs->regs[30]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    u64 sp = 0;
    bpf_probe_read_kernel(&sp, sizeof(sp), &regs->sp);
    save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 2);
    u64 pc = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &regs->pc);
    save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 3);

    int ctx_index = 0;
    op_ctx_t* op_ctx = bpf_map_lookup_elem(&op_ctx_map, &ctx_index);
    // make ebpf verifier happy
    if (unlikely(op_ctx == NULL)) return 0;
    __builtin_memset((void *)op_ctx, 0, sizeof(op_ctx));

    op_ctx->reg_0 = saved_regs.args[0];
    op_ctx->save_index = 4;
    op_ctx->op_key_index = 0;

    read_args(&p, point_args, op_ctx, regs);
    
    if (op_ctx->skip_flag) {
        op_ctx->skip_flag = 0;
        saved_regs.flag = 1;
        save_args(&saved_regs, SYSCALL_ENTER);
        return 0;
    }

    events_perf_submit(&p, SYSCALL_ENTER);
    if (filter->signal > 0) {
        bpf_send_signal(filter->signal);
    }
    if (filter->tsignal > 0) {
        bpf_send_signal_thread(filter->tsignal);
    }
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_syscalls_sys_exit(struct bpf_raw_tracepoint_args* ctx) {

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
    u64 syscallno = READ_KERN(regs->syscallno);
    u32 sysno = (u32)syscallno;

    point_args_t* point_args = bpf_map_lookup_elem(&sysexit_point_args, &sysno);
    if (unlikely(point_args == NULL)) return 0;

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (unlikely(filter == NULL)) return 0;

    args_t saved_regs;
    if (load_args(&saved_regs, SYSCALL_ENTER) != 0) {
        return 0;
    }
    del_args(SYSCALL_ENTER);
    if (saved_regs.flag == 1) {
        return 0;
    }

    if (filter->trace_mode == TRACE_COMMON) {
        // 非 追踪全部syscall模式
        u32 sysno_whitelist_key = sysno + SYS_WHITELIST_START;
        u32 *sysno_whitelist_value = bpf_map_lookup_elem(&common_list, &sysno_whitelist_key);
        if (unlikely(sysno_whitelist_value == NULL)) return 0;
    }

    // 黑名单同样对 追踪全部syscall模式 有效
    u32 sysno_blacklist_key = sysno + SYS_BLACKLIST_START;
    u32 *sysno_blacklist_value = bpf_map_lookup_elem(&common_list, &sysno_blacklist_key);
    if (unlikely(sysno_blacklist_value != NULL)) return 0;

    // 保存系统调用号
    save_to_submit_buf(p.event, (void *) &sysno, sizeof(u32), 0);

    int ctx_index = 1;
    op_ctx_t* op_ctx = bpf_map_lookup_elem(&op_ctx_map, &ctx_index);
    if (unlikely(op_ctx == NULL)) return 0;
    __builtin_memset((void *)op_ctx, 0, sizeof(op_ctx));

    op_ctx->reg_0 = saved_regs.args[0];
    op_ctx->save_index = 1;
    op_ctx->op_key_index = 0;

    read_args(&p, point_args, op_ctx, regs);

    if (op_ctx->skip_flag) {
        op_ctx->skip_flag = 0;
        return 0;
    }

    // 读取返回值
    u64 ret = READ_KERN(regs->regs[0]);
    save_to_submit_buf(p.event, (void *) &ret, sizeof(ret), op_ctx->save_index);

    events_perf_submit(&p, SYSCALL_EXIT);
    return 0;
}


// bpf_printk debug use
// echo 1 > /sys/kernel/tracing/tracing_on
// cat /sys/kernel/tracing/trace_pipe