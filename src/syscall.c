#include "utils.h"
#include <stdbool.h>

#include "types.h"
#include "common/arguments.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filtering.h"

typedef struct syscall_point_args_t {
    u32 nr;
    u32 count;
    point_arg point_args[MAX_POINT_ARG_COUNT];
    point_arg point_arg_ret;
} syscall_point_args;

// syscall_point_args_map 的 key 就是 nr
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct syscall_point_args_t);
    __uint(max_entries, 512);
} syscall_point_args_map SEC(".maps");

typedef struct next_point_args_t {
    u32 op_count;
    u32 op_key_list[MAX_OP_COUNT];
} next_point_args;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct next_point_args_t);
    __uint(max_entries, 512);
} next_point_args_map SEC(".maps");

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
    if (pid == NULL) {
        return 0;
    }
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
int next_raw_syscalls_sys_enter(struct bpf_raw_tracepoint_args* ctx) {

    // 除了实现对指定进程的系统调用跟踪 也要将其产生的子进程 加入追踪范围
    // 为了实现这个目的 fork 系统调用结束之后 应当检查其 父进程是否归属于当前被追踪的进程

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
    u64 syscallno = READ_KERN(regs->syscallno);
    u32 sysno = (u32)syscallno;
    // 先根据调用号确定有没有对应的参数获取方案 没有直接结束
    struct next_point_args_t* point_args = bpf_map_lookup_elem(&next_point_args_map, &sysno);
    if (point_args == NULL) {
        // bpf_printk("[syscall] unsupport nr:%d\n", sysno);
        return 0;
    }

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    if (filter->trace_mode == TRACE_COMMON) {
        // 非 追踪全部syscall模式
        u32 sysno_whitelist_key = sysno + SYS_WHITELIST_START;
        u32 *sysno_whitelist_value = bpf_map_lookup_elem(&common_list, &sysno_whitelist_key);
        if (sysno_whitelist_value == NULL) {
            return 0;
        }
    }

    // 黑名单同样对 追踪全部syscall模式 有效
    u32 sysno_blacklist_key = sysno + SYS_BLACKLIST_START;
    u32 *sysno_blacklist_value = bpf_map_lookup_elem(&common_list, &sysno_blacklist_key);
    if (sysno_blacklist_value != NULL) {
        return 0;
    }

    // 保存寄存器应该放到所有过滤完成之后
    args_t args = {};
    args.args[0] = READ_KERN(regs->regs[0]);
    args.args[1] = READ_KERN(regs->regs[1]);
    args.args[2] = READ_KERN(regs->regs[2]);
    args.args[3] = READ_KERN(regs->regs[3]);
    args.args[4] = READ_KERN(regs->regs[4]);
    args.args[5] = READ_KERN(regs->regs[5]);
    save_args(&args, SYSCALL_ENTER);

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
    u64 pc = 0;
    u64 sp = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &regs->pc);
    bpf_probe_read_kernel(&sp, sizeof(sp), &regs->sp);
    save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 2);
    save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 3);


    // 为了能更深度读取各种类型的数据 重新设计处理逻辑
    // 当前的处理逻辑是先设置好要读取数据的配置 然后ebpf中取出配置
    // 这里的操作是针对每一个要读取的参数做的 有一层for
    // 但是读取的参数结束之后 如果还想要根据配置再进一步读取
    // 那么还得套一层for 一旦套了多层for 那么整个ebpf程序就会变得复杂
    // 加载的时候很容易触发检查不过
    // 新的思路是 将要获取数据的这个过程 全部转换为一个操作列表
    // 不管要读取哪些内容 先将整个过程变成一个列表 这样深层次读取都会变成单个循环
    // 单个循环的处理上限也会好很多 有点vm的意思
    // op_list = [OP_SYSNO, OP_LR, OP_PC, OP_SP, OP_INT, ...]
    // 对于 msghdr 这样的结构体 按照之前的思路 直接读取结构体大小的数据
    // 但是现在改成 依次读取 ptr

    // OP_MSGHDR 读取 Msghdr 结构体大小
    // OP_IOV 读取 IOVEC 结构体大小
    // OP_IOV_BASE 读取 IOVEC->BASE 处 IOVEC->LEN 大小
    // 重复上面的操作 6 次 每次重复都与 Msghdr->Iovlen 比较
    // 这个过程还要处理一些问题 比如某个操作要读取的地址 要读取的长度 从哪里来...
    // 这个必须设计成通用的
    // {op_struct: {op_read_addr, op_read_len}}
    // {op_msghdr: {op_max_iovlen}}
    // {op_msghdr: {op_max_iovlen}}
    // type Msghdr struct {
    //     Name       uint64
    //     Namelen    uint32
    //     Pad_cgo_0  [4]byte
    //     Iov        uint64
    //     Iovlen     uint64
    //     Control    uint64
    //     Controllen uint64
    //     Flags      int32
    //     Pad_cgo_1  [4]byte
    // }
    // type Iovec struct {
    //     Base *byte
    //     Len  uint64
    // }
    // struct msghdr {
    //     void* msg_name;
    //     socklen_t msg_namelen;
    //     struct iovec* msg_iov;
    //     size_t msg_iovlen;
    //     void* msg_control;
    //     size_t msg_controllen;
    //     int msg_flags;
    // };
    // struct iovec {
    //     void *iov_base;
    //     __kernel_size_t iov_len;
    // };

    u32 op_count = MAX_OP_COUNT;
    if (point_args->op_count <= op_count) {
        op_count = point_args->op_count;
    }

    int zero = 0;
    op_ctx_t* op_ctx = bpf_map_lookup_elem(&op_ctx_map, &zero);
    // make ebpf verifier happy
    if (unlikely(op_ctx == NULL)) return 0;

    op_ctx->save_index = 4;

    for (int i = 0; i < op_count; i++) {
        u32 op_key = point_args->op_key_list[i];
        bpf_printk("[stackplz] index:%d op_key:%d\n", i, op_key);
        op_config_t* op = bpf_map_lookup_elem(&op_list, &op_key);
        // make ebpf verifier happy
        if (unlikely(op == NULL)) return 0;

        bpf_printk("[stackplz] op_key:%d code:%d value:%ld\n", op_key, op->code, op->value);

        // 一旦 break_flag 置 1 那么跳过所有操作直到出现 OP_RESET_BREAK
        if (op_ctx->break_flag == 1) {
            if (op->code == OP_RESET_BREAK) {
                op_ctx->break_flag = 0;
            }
            continue;
        }

        switch (op->code) {
            case OP_SKIP:
                break;
            case OP_RESET_CTX:
                op_ctx->break_flag = 0;
                op_ctx->break_count = 0;
                op_ctx->reg_index = 0;
                op_ctx->read_addr = 0;
                op_ctx->read_len = 0;
                op_ctx->reg_value = 0;
                op_ctx->pointer_value = 0;
                break;
            case OP_SET_REG_INDEX:
                op_ctx->reg_index = op->value;
                break;
            case OP_SET_READ_LEN:
                op_ctx->read_len = op->value;
                break;
            case OP_SET_READ_LEN_REG_VALUE:
                if (op_ctx->read_len > op_ctx->reg_value) {
                    op_ctx->read_len = op_ctx->reg_value;
                }
            case OP_SET_READ_LEN_POINTER_VALUE:
                if (op_ctx->read_len > op_ctx->pointer_value) {
                    op_ctx->read_len = op_ctx->pointer_value;
                }
                break;
            case OP_SET_READ_COUNT:
                op_ctx->read_len *= op->value;
                break;
            case OP_ADD_OFFSET:
                op_ctx->read_addr += op->value;
                break;
            case OP_SUB_OFFSET:
                op_ctx->read_addr -= op->value;
                break;
            case OP_MOVE_REG_VALUE:
                op_ctx->read_addr = op_ctx->reg_value;
                break;
            case OP_MOVE_POINTER_VALUE:
                op_ctx->read_addr = op_ctx->pointer_value;
                break;
            case OP_MOVE_TMP_VALUE:
                op_ctx->read_addr = op_ctx->tmp_value;
                break;
            case OP_SET_TMP_VALUE:
                op_ctx->tmp_value = op_ctx->read_addr;
                break;
            case OP_SET_BREAK_COUNT_REG_VALUE:
                op_ctx->break_count = op_ctx->reg_value;
                break;
            case OP_SET_BREAK_COUNT_POINTER_VALUE:
                op_ctx->break_count = op_ctx->pointer_value;
                break;
            case OP_READ_REG:
                // make ebpf verifier happy
                if (op_ctx->reg_index >= REG_ARM64_MAX) {
                    return 0;
                }
                op_ctx->reg_value = READ_KERN(regs->regs[op_ctx->reg_index]);
                break;
            case OP_SAVE_REG:
                save_to_submit_buf(p.event, (void *)&op_ctx->reg_value, sizeof(op_ctx->reg_value), (u8)op_ctx->save_index);
                op_ctx->save_index += 1;
                break;
            case OP_READ_POINTER:
                bpf_probe_read_user(&op_ctx->pointer_value, sizeof(op_ctx->pointer_value), (void*)op_ctx->read_addr);
                break;
            case OP_SAVE_POINTER:
                save_to_submit_buf(p.event, (void *) &op_ctx->pointer_value, sizeof(op_ctx->pointer_value), op_ctx->save_index);
                op_ctx->save_index += 1;
                break;
            case OP_READ_STRUCT:
                break;
            case OP_SAVE_STRUCT:
                // fix memory tag
                op_ctx->read_addr = op_ctx->read_addr & 0xffffffffff;
                if (op_ctx->read_len > MAX_BYTES_ARR_SIZE) {
                    op_ctx->read_len = MAX_BYTES_ARR_SIZE;
                }
                int status = save_bytes_to_buf(p.event, (void *)(op_ctx->read_addr), op_ctx->read_len, op_ctx->save_index);
                if (status == 0) {
                    // 保存失败的情况 比如是一个非法的地址 那么就填一个空的 buf
                    // 那么只会保存 save_index 和 size -> [save_index][size][]
                    // ? 这里的处理方法好像不对 应该没问题 因为失败的时候 buf_off 没有变化
                    save_bytes_to_buf(p.event, 0, 0, op_ctx->save_index);
                }
                op_ctx->save_index += 1;
                break;
            case OP_READ_STRING:
                break;
            case OP_SAVE_STRING:
                // fix memory tag
                op_ctx->read_addr = op_ctx->read_addr & 0xffffffffff;
                save_str_to_buf(p.event, (void*) op_ctx->read_addr, op_ctx->save_index);
                op_ctx->save_index += 1;
                break;
            case OP_FOR_BREAK:
                if (op_ctx->break_count > 0 && op->value >= op_ctx->break_count) {
                    op_ctx->break_flag = 1;
                }
                break;
            case OP_RESET_BREAK:
                op_ctx->break_flag = 0;
                break;
            default:
                // bpf_printk("[stackplz] unknown op code:%d\n", op->code);
                break;
        }
    }
    events_perf_submit(&p, SYSCALL_ENTER);
    if (filter->signal > 0) {
        bpf_send_signal(filter->signal);
    }
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_syscalls_sys_enter(struct bpf_raw_tracepoint_args* ctx) {

    // 除了实现对指定进程的系统调用跟踪 也要将其产生的子进程 加入追踪范围
    // 为了实现这个目的 fork 系统调用结束之后 应当检查其 父进程是否归属于当前被追踪的进程

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
    u64 syscallno = READ_KERN(regs->syscallno);
    u32 sysno = (u32)syscallno;
    // 先根据调用号确定有没有对应的参数获取方案 没有直接结束
    struct syscall_point_args_t* syscall_point_args = bpf_map_lookup_elem(&syscall_point_args_map, &sysno);
    if (syscall_point_args == NULL) {
        // bpf_printk("[syscall] unsupport nr:%d\n", sysno);
        return 0;
    }

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    if (filter->trace_mode == TRACE_COMMON) {
        // 非 追踪全部syscall模式
        u32 sysno_whitelist_key = sysno + SYS_WHITELIST_START;
        u32 *sysno_whitelist_value = bpf_map_lookup_elem(&common_list, &sysno_whitelist_key);
        if (sysno_whitelist_value == NULL) {
            return 0;
        }
    }

    // 黑名单同样对 追踪全部syscall模式 有效
    u32 sysno_blacklist_key = sysno + SYS_BLACKLIST_START;
    u32 *sysno_blacklist_value = bpf_map_lookup_elem(&common_list, &sysno_blacklist_key);
    if (sysno_blacklist_value != NULL) {
        return 0;
    }

    // 保存寄存器应该放到所有过滤完成之后
    args_t args = {};
    args.args[0] = READ_KERN(regs->regs[0]);
    args.args[1] = READ_KERN(regs->regs[1]);
    args.args[2] = READ_KERN(regs->regs[2]);
    args.args[3] = READ_KERN(regs->regs[3]);
    args.args[4] = READ_KERN(regs->regs[4]);
    args.args[5] = READ_KERN(regs->regs[5]);
    save_args(&args, SYSCALL_ENTER);

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
    u64 pc = 0;
    u64 sp = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &regs->pc);
    bpf_probe_read_kernel(&sp, sizeof(sp), &regs->sp);
    save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 2);
    save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 3);

    u32 point_arg_count = MAX_POINT_ARG_COUNT;
    if (syscall_point_args->count <= point_arg_count) {
        point_arg_count = syscall_point_args->count;
    }

    u32 next_arg_index = 4;
    u64 reg_0 = READ_KERN(regs->regs[0]);
    for (int i = 0; i < point_arg_count; i++) {
        struct point_arg_t* point_arg = (struct point_arg_t*) &syscall_point_args->point_args[i];
        if (point_arg->read_index == REG_ARM64_MAX) {
            continue;
        }
        u64 arg_ptr = get_arg_ptr(regs, point_arg, i, reg_0);

        // 先保存参数值本身
        save_to_submit_buf(p.event, (void *)&arg_ptr, sizeof(u64), (u8)next_arg_index);
        next_arg_index += 1;

        if (point_arg->point_flag != SYS_ENTER) {
            continue;
        }
        if (arg_ptr == 0) {
            continue;
        }
        u32 read_count = get_read_count(regs, point_arg);
        next_arg_index = read_arg(p, point_arg, arg_ptr, read_count, next_arg_index);
        if (point_arg->tmp_index == FILTER_INDEX_SKIP) {
            point_arg->tmp_index = 0;
            args.flag = 1;
            save_args(&args, SYSCALL_ENTER);
            return 0;
        }
    }
    events_perf_submit(&p, SYSCALL_ENTER);
    if (filter->signal > 0) {
        bpf_send_signal(filter->signal);
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

    struct syscall_point_args_t* syscall_point_args = bpf_map_lookup_elem(&syscall_point_args_map, &sysno);
    if (syscall_point_args == NULL) {
        return 0;
    }

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    args_t saved_args;
    if (load_args(&saved_args, SYSCALL_ENTER) != 0) {
        return 0;
    }
    del_args(SYSCALL_ENTER);
    if (saved_args.flag == 1) {
        return 0;
    }

    if (filter->trace_mode == TRACE_COMMON) {
        // 非 追踪全部syscall模式
        u32 sysno_whitelist_key = sysno + SYS_WHITELIST_START;
        u32 *sysno_whitelist_value = bpf_map_lookup_elem(&common_list, &sysno_whitelist_key);
        if (sysno_whitelist_value == NULL) {
            return 0;
        }
    }

    // 黑名单同样对 追踪全部syscall模式 有效
    u32 sysno_blacklist_key = sysno + SYS_BLACKLIST_START;
    u32 *sysno_blacklist_value = bpf_map_lookup_elem(&common_list, &sysno_blacklist_key);
    if (sysno_blacklist_value != NULL) {
        return 0;
    }

    u32 next_arg_index = 0;
    save_to_submit_buf(p.event, (void *) &sysno, sizeof(u32), (u8)next_arg_index);
    next_arg_index += 1;

    u32 point_arg_count = MAX_POINT_ARG_COUNT;
    if (syscall_point_args->count <= point_arg_count) {
        point_arg_count = syscall_point_args->count;
    }
    u64 reg_0 = saved_args.args[0];
    for (int i = 0; i < point_arg_count; i++) {
        struct point_arg_t* point_arg = (struct point_arg_t*) &syscall_point_args->point_args[i];
        if (point_arg->read_index == REG_ARM64_MAX) {
            continue;
        }
        u64 arg_ptr = get_arg_ptr(regs, point_arg, i, reg_0);

        // 先保存参数值本身
        save_to_submit_buf(p.event, (void *)&arg_ptr, sizeof(u64), (u8)next_arg_index);
        next_arg_index += 1;

        if (point_arg->point_flag != SYS_EXIT) {
            continue;
        }
        if (arg_ptr == 0) {
            continue;
        }
        u32 read_count = get_read_count(regs, point_arg);
        next_arg_index = read_arg(p, point_arg, arg_ptr, read_count, next_arg_index);
    }

    // 读取返回值
    u64 ret = READ_KERN(regs->regs[0]);
    // 保存之
    save_to_submit_buf(p.event, (void *) &ret, sizeof(ret), (u8)next_arg_index);
    next_arg_index += 1;
    // 取返回值的参数配置 并尝试进一步读取
    struct point_arg_t* point_arg = (struct point_arg_t*) &syscall_point_args->point_arg_ret;
    next_arg_index = read_arg(p, point_arg, ret, 0, next_arg_index);
    // 发送数据
    events_perf_submit(&p, SYSCALL_EXIT);
    return 0;
}

// bpf_printk debug use
// echo 1 > /sys/kernel/tracing/tracing_on
// cat /sys/kernel/tracing/trace_pipe