#include "utils.h"
// #include "soinfo_android12_r3.h"
#include <stdbool.h>

#include "types.h"
#include "common/arguments.h"
#include "common/buffer.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filesystem.h"
#include "common/filtering.h"
#include "common/probes.h"


// uprobe hook

struct uprobe_stack_event_t {
    u32 pid;
    u32 tid;
    u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} stack_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct uprobe_stack_event_t);
    __uint(max_entries, 1);
} uprobe_stack_event_heap SEC(".maps");

// 用于设置过滤配置
struct uprobe_stack_filter_t {
    u32 uid;
    u32 pid;
    u32 tid;
    u32 tids_blacklist_mask;
    u32 tids_blacklist[MAX_COUNT];
    u32 pids_blacklist_mask;
    u32 pids_blacklist[MAX_COUNT];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct uprobe_stack_filter_t);
    __uint(max_entries, 1);
} uprobe_stack_filter SEC(".maps");

SEC("uprobe/stack")
int probe_stack(struct pt_regs* ctx) {
    u32 filter_key = 0;
    struct uprobe_stack_filter_t* filter = bpf_map_lookup_elem(&uprobe_stack_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    // 获取信息用于过滤
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u32 tid = current_pid_tgid & 0xffffffff;
    // uid 过滤
    if (filter->uid != MAGIC_UID && filter->uid != uid) {
        return 0;
    }
    // pid 过滤
    if (filter->pid != MAGIC_PID && filter->pid != pid) {
        return 0;
    }
    // tid 过滤
    if (filter->tid != MAGIC_TID && filter->tid != tid) {
        return 0;
    }

    // tid 黑名单过滤
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->tids_blacklist_mask & (1 << i))) {
            if (filter->tids_blacklist[i] == tid) {
                return 0;
            }
        } else {
            break;
        }
    }
    // pid 黑名单过滤
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->pids_blacklist_mask & (1 << i))) {
            if (filter->pids_blacklist[i] == tid) {
                return 0;
            }
        } else {
            break;
        }
    }

    u32 zero = 0;
    struct uprobe_stack_event_t* event = bpf_map_lookup_elem(&uprobe_stack_event_heap, &zero);
    if (event == NULL) {
        return 0;
    }

    event->pid = pid;
    event->tid = tid;
    event->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    long status = bpf_perf_event_output(ctx, &stack_events, BPF_F_CURRENT_CPU, event, sizeof(struct uprobe_stack_event_t));

    #ifdef DEBUG_PRINT
    if (status != 0) {
        char perf_msg_fmt[] = "bpf_perf_event_output, uid:%d pid:%d tid:%d status:%d\n";
        bpf_trace_printk(perf_msg_fmt, sizeof(perf_msg_fmt), uid, pid, tid, status);
    }
    #endif

    return 0;
}

// raw_tracepoint hook

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} syscall_events SEC(".maps");


typedef struct point_arg_t {
    u32 read_flag;
    u32 alias_type;
    u32 type;
    u32 size;
} point_arg;

#define MAX_POINT_ARG_COUNT 6
// typedef struct point_args_t {
//     u32 count;
//     point_arg_t point_args[MAX_POINT_ARG_COUNT];
// } point_args;

typedef struct syscall_point_args_t {
    // u32 nr;
    u32 count;
    point_arg point_args[MAX_POINT_ARG_COUNT];
    point_arg point_arg_ret;
} syscall_point_args;

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, u32);
//     __type(value, struct point_args_t);
//     __uint(max_entries, 512);
// } point_args_map SEC(".maps");

// syscall_point_args_map 的 key 就是 nr
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct syscall_point_args_t);
    __uint(max_entries, 512);
} syscall_point_args_map SEC(".maps");

// struct arg_ret_mask_t {
//     u32 ret_mask;
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, u32);
//     __type(value, struct arg_ret_mask_t);
//     __uint(max_entries, 512);
// } arg_ret_mask_map SEC(".maps");

// syscall过滤配置
struct syscall_filter_t {
    u32 is_32bit;
    u32 after_read;
    // u32 tids_blacklist_mask;
    // u32 tids_blacklist[MAX_COUNT];
    // u32 pids_blacklist_mask;
    // u32 pids_blacklist[MAX_COUNT];
    u32 syscall_mask;
    u32 syscall[MAX_COUNT];
    u32 syscall_blacklist_mask;
    u32 syscall_blacklist[MAX_COUNT];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct syscall_filter_t);
    __uint(max_entries, 1);
} syscall_filter SEC(".maps");


static __always_inline u32 read_args(program_data_t p, struct point_arg_t* point_arg, u64 ptr, u32 next_arg_index) {
    if (point_arg->type == TYPE_NONE) {
        return next_arg_index;
    }
    if (point_arg->type == TYPE_NUM) {
        // 这种具体类型转换交给前端做
        return next_arg_index;
    }
    if (point_arg->type == TYPE_STRING) {
        u32 buf_off = 0;
        buf_t *string_p = get_buf(STRING_BUF_IDX);
        if (string_p == NULL) {
            return next_arg_index;
        }
        bpf_probe_read_user(&string_p->buf[buf_off], MAX_STRING_SIZE, (void *)ptr);
        save_str_to_buf(p.event, &string_p->buf[buf_off], next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    if (point_arg->type == TYPE_POINTER) {
        // 指针类型 通常读一下对应指针的数据即可 后续记得考虑兼容下32位
        
        // point_arg->alias_type
        // 某些成员是指针 有可能有必要再深入读取
        // 这个时候可以根据 alias_type 取出对应的参数配置 然后解析保存
        // 这个后面增补

        u64 addr = 0;
        bpf_probe_read_kernel(&addr, sizeof(addr), (void*) ptr);
        save_to_submit_buf(p.event, (void *) &addr, sizeof(u64), next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    if (point_arg->type == TYPE_STRUCT && ptr != 0) {
        // 结构体类型 直接读取对应大小的数据 具体转换交给前端
        u32 struct_size = MAX_BYTES_ARR_SIZE;
        if (point_arg->size <= struct_size) {
            struct_size = point_arg->size;
        }
        save_bytes_to_buf(p.event, (void *)ptr, struct_size, next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    return next_arg_index;
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
    // 到这里的说明是命中了 追踪范围
    // bpf_printk("[syscall] after should_trace uid:%d pid:%d host_pid:%d\n", p.event->context.uid, p.event->context.pid, p.event->context.host_pid);
    // 先收集下寄存器
    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);
    args_t args = {};
    args.args[0] = READ_KERN(regs->regs[0]);
    args.args[1] = READ_KERN(regs->regs[1]);
    args.args[2] = READ_KERN(regs->regs[2]);
    args.args[3] = READ_KERN(regs->regs[3]);
    args.args[4] = READ_KERN(regs->regs[4]);
    if (save_args(&args, SYSCALL_ENTER) != 0) {
        return 0;
    };

    u64 syscallno = READ_KERN(regs->syscallno);

    u32 filter_key = 0;
    struct syscall_filter_t* filter = bpf_map_lookup_elem(&syscall_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    // syscall 白名单过滤
    bool has_find = false;
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->syscall_mask & (1 << i))) {
            if (filter->syscall[i] == (u32)syscallno) {
                // bpf_printk("[syscall] xx syscallno:%d mask:%d\n", syscallno, filter->syscall_mask);
                has_find = true;
                break;
            }
        } else {
            if (i == 0) {
                // 如果没有设置白名单 则将 has_find 置为 true
                has_find = true;
            }
            // 减少不必要的循环
            break;
        }
    }
    // 不满足白名单规则 则跳过
    if (!has_find) {
        return 0;
    }

    // syscall 黑名单过滤
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->syscall_blacklist_mask & (1 << i))) {
            if (filter->syscall_blacklist[i] == (u32)syscallno) {
                // 在syscall黑名单直接结束跳过
                return 0;
            }
        } else {
            // 减少不必要的循环
            break;
        }
    }

    // 线程名过滤？后面考虑有没有必要
    // 渲染相关的线程 属实没必要 太多调用了
    char thread_blacklist[9][15] = {
        "RenderThread",
        "RxCachedThreadS",
        "mali-cmar-backe",
        "mali-utility-wo",
        "mali-mem-purge",
        "mali-hist-dump",
        "hwuiTask0",
        "hwuiTask1",
        "NDK MediaCodec_",
    };
    #pragma unroll
    for (int i = 0; i < 9; i++) {
        bool need_skip = true;
        #pragma unroll
        for (int j = 0; j < 15; j++) {
            if (thread_blacklist[i][j] == 0) break;
            if (p.event->context.comm[j] != thread_blacklist[i][j]) {
                need_skip = false;
                break;
            }
        }
        if (need_skip) {
            return 0;
        }
    }

    // event->context 已经有进程的信息了
    save_to_submit_buf(p.event, (void *) &syscallno, sizeof(u32), 0);

    // 先获取 lr sp pc 并发送 这样可以尽早计算调用来源情况
    // READ_KERN 好像有问题
    if(filter->is_32bit) {
        u64 lr = 0;
        bpf_probe_read_kernel(&lr, sizeof(lr), &regs->regs[14]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    else {
        u64 lr = 0;
        bpf_probe_read_kernel(&lr, sizeof(lr), &regs->regs[30]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    u64 pc = 0;
    u64 sp = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &regs->pc);
    bpf_probe_read_kernel(&sp, sizeof(sp), &regs->sp);
    save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 2);
    save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 3);

    struct syscall_point_args_t* syscall_point_args = bpf_map_lookup_elem(&syscall_point_args_map, &syscallno);
    if (syscall_point_args == NULL) {
        return 0;
    }
    u32 point_arg_count = MAX_POINT_ARG_COUNT;
    if (syscall_point_args->count <= point_arg_count) {
        point_arg_count = syscall_point_args->count;
    }

    int next_arg_index = 4;
    // #pragma unroll
    for (int i = 0; i < point_arg_count; i++) {
        // 先保存寄存器
        save_to_submit_buf(p.event, (void *)&args.args[i], sizeof(u64), next_arg_index);
        next_arg_index += 1;
        struct point_arg_t* point_arg = (struct point_arg_t*) &syscall_point_args->point_args[i];
        if (point_arg->read_flag != SYS_ENTER) {
            continue;
        }
        next_arg_index = read_args(p, point_arg, args.args[i], next_arg_index);
    }
    events_perf_submit(&p, SYSCALL_ENTER);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_syscalls_sys_exit(struct bpf_raw_tracepoint_args* ctx) {

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    u32 filter_key = 0;
    struct syscall_filter_t* filter = bpf_map_lookup_elem(&syscall_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    args_t saved_args;
    if (load_args(&saved_args, SYSCALL_ENTER) != 0) {
        return 0;
    }

    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);
    u64 syscallno = READ_KERN(regs->syscallno);

    // syscall 白名单过滤
    bool has_find = false;
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->syscall_mask & (1 << i))) {
            if (filter->syscall[i] == (u32)syscallno) {
                has_find = true;
                break;
            }
        } else {
            if (i == 0) {
                // 如果没有设置白名单 则将 has_find 置为 true
                has_find = true;
            }
            // 减少不必要的循环
            break;
        }
    }
    // 不满足白名单规则 则跳过
    if (!has_find) {
        return 0;
    }

    // syscall 黑名单过滤
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->syscall_blacklist_mask & (1 << i))) {
            if (filter->syscall_blacklist[i] == (u32)syscallno) {
                // 在syscall黑名单直接结束跳过
                return 0;
            }
        } else {
            // 减少不必要的循环
            break;
        }
    }

    char thread_blacklist[9][15] = {
        "RenderThread",
        "RxCachedThreadS",
        "mali-cmar-backe",
        "mali-utility-wo",
        "mali-mem-purge",
        "mali-hist-dump",
        "hwuiTask0",
        "hwuiTask1",
        "NDK MediaCodec_",
    };
    #pragma unroll
    for (int i = 0; i < 9; i++) {
        bool need_skip = true;
        #pragma unroll
        for (int j = 0; j < 15; j++) {
            if (thread_blacklist[i][j] == 0) break;
            if (p.event->context.comm[j] != thread_blacklist[i][j]) {
                need_skip = false;
                break;
            }
        }
        if (need_skip) {
            return 0;
        }
    }

    struct syscall_point_args_t* syscall_point_args = bpf_map_lookup_elem(&syscall_point_args_map, &syscallno);
    if (syscall_point_args == NULL) {
        return 0;
    }

    int next_arg_index = 0;
    save_to_submit_buf(p.event, (void *) &syscallno, sizeof(u32), next_arg_index);
    next_arg_index += 1;

    u32 point_arg_count = MAX_POINT_ARG_COUNT;
    if (syscall_point_args->count <= point_arg_count) {
        point_arg_count = syscall_point_args->count;
    }
    // #pragma unroll
    for (int i = 0; i < point_arg_count; i++) {
        // 保存参数的寄存器
        save_to_submit_buf(p.event, (void *)&saved_args.args[i], sizeof(u64), next_arg_index);
        next_arg_index += 1;
        struct point_arg_t* point_arg = (struct point_arg_t*) &syscall_point_args->point_args[i];
        if (point_arg->read_flag != SYS_EXIT) {
            continue;
        }
        next_arg_index = read_args(p, point_arg, saved_args.args[i], next_arg_index);
    }
    // 读取返回值
    u64 ret = READ_KERN(regs->regs[0]);
    // 保存之
    save_to_submit_buf(p.event, (void *) &ret, sizeof(ret), next_arg_index);
    next_arg_index += 1;
    // 取返回值的参数配置 并尝试进一步读取
    struct point_arg_t* point_arg = (struct point_arg_t*) &syscall_point_args->point_arg_ret;
    next_arg_index = read_args(p, point_arg, ret, next_arg_index);
    // 发送数据
    events_perf_submit(&p, SYSCALL_EXIT);
    return 0;
}