#include "common.h"
#include "buffer.h"
#include "soinfo_android12_r3.h"
#include <stdbool.h>

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
    if (filter->uid != 0 && filter->uid != uid) {
        return 0;
    }
    // pid 过滤
    if (filter->pid != 0 && filter->pid != pid) {
        return 0;
    }
    // tid 过滤
    if (filter->tid != 0 && filter->tid != tid) {
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

struct syscall_data_t {
    u32 pid;
    u32 tid;
    u32 type;
    u32 syscall_id;
    u64 lr;
    u64 sp;
    u64 pc;
    u64 ret;
    u64 arg_index;
    u64 args[6];
    char comm[16];
    char arg_str[512];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} syscall_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct syscall_data_t);
    __uint(max_entries, 1);
} syscall_data_buffer_heap SEC(".maps");

// 用于指明哪些参数是string类型的mask
struct arg_mask_t {
    u32 mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct arg_mask_t);
    __uint(max_entries, 512);
} arg_mask_map SEC(".maps");

struct arg_ret_mask_t {
    u32 ret_mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct arg_ret_mask_t);
    __uint(max_entries, 512);
} arg_ret_mask_map SEC(".maps");

// syscall过滤配置
struct syscall_filter_t {
    u32 uid;
    u32 pid;
    u32 tid;
    u32 tids_blacklist_mask;
    u32 tids_blacklist[MAX_COUNT];
    u32 pids_blacklist_mask;
    u32 pids_blacklist[MAX_COUNT];
    u32 is_32bit;
    // u32 try_bypass;
    u32 after_read;
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

#define EventTypeSysEnter 1
#define EventTypeSysEnterArgs 2
#define EventTypeSysEnterRegs 3
#define EventTypeSysExitReadAfterArgs 4
#define EventTypeSysExitArgs 5
#define EventTypeSysExitRet 6

static int inline send_data_arg_str(struct bpf_raw_tracepoint_args* ctx, struct syscall_data_t* data, u64 addr, u32 data_type) {
    // u32 filter_key = 0;
    // struct syscall_filter_t* filter = bpf_map_lookup_elem(&syscall_filter, &filter_key);
    // if (filter == NULL) {
    //     return 0;
    // }
    // if (filter->try_bypass) {
    //     char target[5][18] = {
    //         "/dev/.magisk",
    //         "/system/bin/magisk",
    //         "/system/bin/su",
    //         "which su",
    //         "mount",
    //     };
    //     #pragma unroll
    //     for (int i = 0; i < 5; i++) {
    //         bool need_override = true;
    //         #pragma unroll
    //         for (int j = 0; j < 18; j++) {
    //             if (target[i][j] == 0) break;
    //             if (data->arg_str[j] != target[i][j]) {
    //                 need_override = false;
    //                 break;
    //             }
    //         }
    //         if (need_override) {
    //             // char fmt0[] = "hit rule, lets bypass it, uid:%s\n";
    //             // bpf_trace_printk(fmt0, sizeof(fmt0), data->arg_str);
    //             char placeholder[] = "/estrace/is/watching/you";
    //             bpf_probe_write_user((void*)addr, placeholder, sizeof(placeholder));
    //         }
    //     }
    // }
    data->type = data_type;
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, data, sizeof(struct syscall_data_t));
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_syscalls_sys_enter(struct bpf_raw_tracepoint_args* ctx) {

    u32 filter_key = 0;
    struct syscall_filter_t* filter = bpf_map_lookup_elem(&syscall_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    // 获取信息用于过滤
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u32 tid = current_pid_tgid & 0xffffffff;
    // uid 过滤
    if (filter->uid != 0 && filter->uid != uid) {
        return 0;
    }
    // pid 过滤
    if (filter->pid != 0 && filter->pid != pid) {
        return 0;
    }
    // tid 黑名单过滤
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->tids_blacklist_mask & (1 << i))) {
            if (filter->tids_blacklist[i] == tid) {
                // 在tid黑名单直接结束跳过
                return 0;
            }
        } else {
            // 减少不必要的循环
            break;
        }
    }

    // syscall 白名单过滤
    bool has_find = false;
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->syscall_mask & (1 << i))) {
            if (filter->syscall[i] == ctx->args[1]) {
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
            if (filter->syscall_blacklist[i] == ctx->args[1]) {
                // 在syscall黑名单直接结束跳过
                return 0;
            }
        } else {
            // 减少不必要的循环
            break;
        }
    }

    // 读取参数 字符串类型的根据预设mask读取并分组发送
    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);

    u32 zero = 0;
    struct syscall_data_t* data = bpf_map_lookup_elem(&syscall_data_buffer_heap, &zero);
    if (data == NULL) {
        return 0;
    }
    // 获取字符串参数类型配置
    struct arg_mask_t* arg_mask = bpf_map_lookup_elem(&arg_mask_map, &data->syscall_id);
    if (arg_mask == NULL) {
        return 0;
    }

    // 获取线程名
    __builtin_memset(&data->comm, 0, sizeof(data->comm));
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

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
            if (data->comm[j] != thread_blacklist[i][j]) {
                need_skip = false;
                break;
            }
        }
        if (need_skip) {
            return 0;
        }
    }

    // 基本信息
    data->pid = pid;
    data->tid = tid;
    data->syscall_id = ctx->args[1];

    // 先获取 lr sp pc 并发送 这样可以尽早计算调用来源情况
    if(filter->is_32bit) {
        bpf_probe_read_kernel(&data->lr, sizeof(data->lr), &regs->regs[14]);
    }
    else {
        bpf_probe_read_kernel(&data->lr, sizeof(data->lr), &regs->regs[30]);
    }
    bpf_probe_read_kernel(&data->pc, sizeof(data->pc), &regs->pc);
    bpf_probe_read_kernel(&data->sp, sizeof(data->sp), &regs->sp);
    __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
    data->type = EventTypeSysEnter;
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, data, sizeof(struct syscall_data_t));

    // 获取参数
    if ((filter->is_32bit && data->syscall_id == 11) || (!filter->is_32bit && data->syscall_id == 221)) {
        // execve 3个参数
        // const char *filename char *const argv[] char *const envp[]
        // 下面的写法是基于已知参数类型构成为前提
        #pragma unroll
        for (int j = 0; j < 3; j++) {
            data->arg_index = j;
            bpf_probe_read_kernel(&data->args[j], sizeof(u64), &regs->regs[j]);
            if (data->args[j] == 0) continue;
            if (j == 0) {
                __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
                bpf_probe_read_user(data->arg_str, sizeof(data->arg_str), (void*)data->args[j]);
                send_data_arg_str(ctx, data, data->args[j], EventTypeSysEnterArgs);
            } else {
                // 最多遍历得到6个子参数
                for (int i = 0; i < 6; i++) {
                    __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
                    void* ptr = (void*)(data->args[j] + 8 * i);
                    u64 addr = 0x0;
                    // 这里应该用 bpf_probe_read_user 而不是 bpf_probe_read_kernel
                    bpf_probe_read_user(&addr, sizeof(u64), ptr);
                    if (addr != 0) {
                        bpf_probe_read_user(data->arg_str, sizeof(data->arg_str), (void*)addr);
                        send_data_arg_str(ctx, data, addr, EventTypeSysEnterArgs);
                    } else {
                        // 遇到为NULL的 直接结束内部遍历
                        break;
                    }
                }
            }
        }
    } else if ((filter->is_32bit && data->syscall_id == 387) || (!filter->is_32bit && data->syscall_id == 281)) {
        // int execveat(int dirfd, const char *pathname, const char *const argv[], const char *const envp[], int flags);
        #pragma unroll
        for (int j = 0; j < 5; j++) {
            data->arg_index = j;
            bpf_probe_read_kernel(&data->args[j], sizeof(u64), &regs->regs[j]);
            if (data->args[j] == 0) continue;
            if (!(arg_mask->mask & (1 << j))) continue;
            if (j == 1) {
                __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
                bpf_probe_read_user(data->arg_str, sizeof(data->arg_str), (void*)data->args[j]);
                send_data_arg_str(ctx, data, data->args[j], EventTypeSysEnterArgs);
            } else {
                for (int i = 0; i < 6; i++) {
                    __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
                    void* ptr = (void*)(data->args[j] + 8 * i);
                    u64 addr = 0x0;
                    bpf_probe_read_user(&addr, sizeof(u64), ptr);
                    if (addr != 0) {
                        bpf_probe_read_user(data->arg_str, sizeof(data->arg_str), (void*)addr);
                        send_data_arg_str(ctx, data, addr, EventTypeSysEnterArgs);
                    } else {
                        break;
                    }
                }
            }
        }
    } else if ((filter->is_32bit && data->syscall_id == 162) || (!filter->is_32bit && data->syscall_id == 101)) {
        struct timespec {
            long tv_sec;        /* seconds */
            long   tv_nsec;       /* nanoseconds */
        };
        // int nanosleep(const struct timespec *req, struct timespec *rem);
        #pragma unroll
        for (int j = 0; j < 2; j++) {
            data->arg_index = j;
            bpf_probe_read_kernel(&data->args[j], sizeof(u64), &regs->regs[j]);
            if (data->args[j] != 0) {
                __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
                bpf_probe_read_user(data->arg_str, sizeof(struct timespec), (void*)data->args[j]);
                data->type = EventTypeSysEnterArgs;
                bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, data, sizeof(struct syscall_data_t));
            }
        }
    } else {
        // 可能是展开循环或者处于else分支的原因 这里必须得重新获取一次 arg_mask
        struct arg_mask_t* arg_mask = bpf_map_lookup_elem(&arg_mask_map, &data->syscall_id);
        if (arg_mask == NULL) {
            return 0;
        }
        // 展开循环
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            bpf_probe_read_kernel(&data->args[i], sizeof(u64), &regs->regs[i]);
            // 栈空间大小限制 分组发送
            if (arg_mask->mask & (1 << i)) {
                data->arg_index = i;
                __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
                // bpf_probe_read_str 读取出来有的内容部分是空 结果中不会有NUL
                // bpf_probe_read_user 读取出来有的内容极少是空 但许多字符串含有NUL
                // bpf_probe_read_user_str 读取出来有的内容部分是空 结果中不会有NUL
                // 综合测试使用 bpf_probe_read_user 最合理 在前端处理 NUL
                // 不过仍然有部分结果是空 调整大小又能读到 原因未知
                bpf_probe_read_user(data->arg_str, sizeof(data->arg_str), (void*)data->args[i]);
                send_data_arg_str(ctx, data, data->args[i], EventTypeSysEnterArgs);
            }
        }
    }
    // 这里会得到完整参数对应的寄存器信息
    __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
    data->type = EventTypeSysEnterRegs;
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, data, sizeof(struct syscall_data_t));
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_syscalls_sys_exit(struct bpf_raw_tracepoint_args* ctx) {
    u32 filter_key = 0;
    struct syscall_filter_t* filter = bpf_map_lookup_elem(&syscall_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    // 获取信息用于过滤
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u32 tid = current_pid_tgid & 0xffffffff;
    // uid过滤
    if (filter->uid != 0 && filter->uid != uid) {
        return 0;
    }
    // pid过滤
    if (filter->pid != 0 && filter->pid != pid) {
        return 0;
    }
    // tid 黑名单过滤
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->tids_blacklist_mask & (1 << i))) {
            if (filter->tids_blacklist[i] == tid) {
                // 在tid黑名单直接结束跳过
                return 0;
            }
        } else {
            // 减少不必要的循环
            break;
        }
    }

    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);

    u32 zero = 0;
    struct syscall_data_t* data = bpf_map_lookup_elem(&syscall_data_buffer_heap, &zero);
    if (data == NULL) {
        return 0;
    }

    if(filter->is_32bit) {
        bpf_probe_read_kernel(&data->syscall_id, sizeof(data->syscall_id), &regs->regs[7]);
    }
    else {
        bpf_probe_read_kernel(&data->syscall_id, sizeof(data->syscall_id), &regs->regs[8]);
    }

    // syscall 白名单过滤
    bool has_find = false;
    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->syscall_mask & (1 << i))) {
            if (filter->syscall[i] == data->syscall_id) {
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
            if (filter->syscall_blacklist[i] == data->syscall_id) {
                // 在syscall黑名单直接结束跳过
                return 0;
            }
        } else {
            // 减少不必要的循环
            break;
        }
    }

    // 获取线程名
    __builtin_memset(&data->comm, 0, sizeof(data->comm));
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

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
            if (data->comm[j] != thread_blacklist[i][j]) {
                need_skip = false;
                break;
            }
        }
        if (need_skip) {
            return 0;
        }
    }

    // 基本信息
    data->pid = pid;
    data->tid = tid;

    // 获取字符串参数类型配置
    struct arg_mask_t* arg_mask = bpf_map_lookup_elem(&arg_mask_map, &data->syscall_id);
    if (arg_mask == NULL) {
        return 0;
    }
    if (filter->after_read) {
        // 这个函数起初是用于对比 syscall 执行前后参数变化的 一般用不到
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            bpf_probe_read_kernel(&data->args[i], sizeof(u64), &regs->regs[i]);
            if (arg_mask->mask & (1 << i)) {
                data->arg_index = i;
                __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
                bpf_probe_read_user(data->arg_str, sizeof(data->arg_str), (void*)data->args[i]);
                send_data_arg_str(ctx, data, data->args[i], EventTypeSysExitReadAfterArgs);
            }
        }
    }

    struct arg_mask_t* arg_ret_mask = bpf_map_lookup_elem(&arg_ret_mask_map, &data->syscall_id);
    if (arg_ret_mask == NULL) {
        return 0;
    }

    // 在执行syscall之后 原本的传入参数才会有值 在这里读取
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        bpf_probe_read_kernel(&data->args[i], sizeof(u64), &regs->regs[i]);
        if (arg_ret_mask->mask & (1 << i)) {
            data->arg_index = i;
            __builtin_memset(&data->arg_str, 0, sizeof(data->arg_str));
            bpf_probe_read_user(data->arg_str, sizeof(data->arg_str), (void*)data->args[i]);
            send_data_arg_str(ctx, data, data->args[i], EventTypeSysExitArgs);
        }
    }

    // 发送返回结果 返回值可能是字符串 后续加上读取
    data->type = EventTypeSysExitRet;
    data->ret = ctx->args[1];
    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, data, sizeof(struct syscall_data_t));
    return 0;
}

// <-----------------------soinfo------------------------->

struct soinfo_data_t {
    u32 pid;
    u32 tid;
    char comm[16];
    u64 base_addr;
    u64 lib_size;
    char realpath[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} soinfo_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct soinfo_data_t);
    __uint(max_entries, 1);
} soinfo_data_buffer_heap SEC(".maps");

// soinfo过滤配置
struct soinfo_filter_t {
    u32 uid;
    u32 pid;
    u32 is_32bit;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct soinfo_filter_t);
    __uint(max_entries, 1);
} soinfo_filter SEC(".maps");

SEC("uprobe/soinfo")
int probe_soinfo(struct pt_regs* ctx) {
    u32 filter_key = 0;
    struct soinfo_filter_t* filter = bpf_map_lookup_elem(&soinfo_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (filter->uid != 0 && filter->uid != uid) {
        return 0;
    }

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u32 tid = current_pid_tgid & 0xffffffff;
    if (filter->pid != 0 && filter->pid != pid) {
        return 0;
    }

    u32 zero = 0;
    struct soinfo_data_t* event = bpf_map_lookup_elem(&soinfo_data_buffer_heap, &zero);
    if (event == NULL) {
        return 0;
    }

    event->pid = pid;
    event->tid = tid;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // 直接 bpf_probe_read_user 读取soinfo数据 解析工作交给前端
    
    bpf_probe_read_user(&event->base_addr, sizeof(event->base_addr), (void*)(ctx->regs[0] + SOINFO_BASE));
    bpf_probe_read_user(&event->lib_size, sizeof(event->lib_size), (void*)(ctx->regs[0] + SOINFO_SIZE));

    u8 tiny_flag = 0;
    u64 so_path_ptr = ctx->regs[0] + SOINFO_REALPATH;
    bpf_probe_read_user(&tiny_flag, sizeof(tiny_flag), (void*)so_path_ptr);
    u64 addr = 0x0;
    if ((tiny_flag & 1) != 0) {
        bpf_probe_read_user(&addr, sizeof(addr), (void*)(so_path_ptr + 2 * 8));
    } else {
        addr = so_path_ptr + 1;
    }
    __builtin_memset(&event->realpath, 0, sizeof(event->realpath));
    bpf_probe_read_user_str(event->realpath, sizeof(event->realpath), (void*)addr);

    long status = bpf_perf_event_output(ctx, &soinfo_events, BPF_F_CURRENT_CPU, event, sizeof(struct soinfo_data_t));

    // char perf_msg_fmt[] = "[soinfo], x0:0x%lx pid:%d status:%d\n";
    // bpf_trace_printk(perf_msg_fmt, sizeof(perf_msg_fmt), ctx->regs[0], pid, status);
    return 0;
}

// vmainfo过滤配置
struct vmainfo_filter_t {
    u32 uid;
    u32 pid;
    u32 is_32bit;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct vmainfo_filter_t);
    __uint(max_entries, 1);
} vmainfo_filter SEC(".maps");

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_security_file_mprotect) {
    u32 filter_key = 0;
    struct vmainfo_filter_t* filter = bpf_map_lookup_elem(&vmainfo_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (filter->uid != 0 && filter->uid != uid) {
        return 0;
    }

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u32 tid = current_pid_tgid & 0xffffffff;
    if (filter->pid != 0 && filter->pid != pid) {
        return 0;
    }

    struct vm_area_struct *vma = (struct vm_area_struct *) PT_REGS_PARM1(ctx);
    struct file *file = (struct file *) READ_KERN(vma->vm_file);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return 0;

    // vm_file_path = smith_d_path(&vma->vm_file->f_path, vm_file_buff, PATH_MAX);
    long sz = bpf_d_path(&file->f_path, (char *)&string_p, PATH_MAX);

    char perf_msg_fmt[] = "[vmainfo] pid:%d sz:%ld name:%s\n";
    bpf_trace_printk(perf_msg_fmt, sizeof(perf_msg_fmt), pid, sz, string_p->buf);

    return 0;
}