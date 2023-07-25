#include "utils.h"
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

#define MAX_POINT_ARG_COUNT 6

typedef struct point_arg_t {
    u32 read_flag;
    u32 alias_type;
    u32 type;
    u32 size;
	u32 item_persize;
	s32 item_countindex;
} point_arg;

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

static __always_inline u32 save_bytes_with_len(program_data_t p, u64 ptr, u32 read_len, u32 next_arg_index) {
    if (read_len > MAX_BUF_READ_SIZE) {
        read_len = MAX_BUF_READ_SIZE;
    }
    int status = save_bytes_to_buf(p.event, (void *)(ptr & 0xffffffffff), read_len, next_arg_index);
    if (status == 0) {
        buf_t *zero_p = get_buf(ZERO_BUF_IDX);
        if (zero_p == NULL) {
            return next_arg_index;
        }
        save_bytes_to_buf(p.event, &zero_p->buf[0], read_len, next_arg_index);
    }
    next_arg_index += 1;
    return next_arg_index;
}
static __always_inline u32 read_arg(program_data_t p, struct point_arg_t* point_arg, u64 ptr, u32 read_count, u32 next_arg_index) {
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
        int status = bpf_probe_read_user(&string_p->buf[buf_off], MAX_STRING_SIZE, (void *)ptr);
        if (status < 0) {
            // MTE 其实也正常读取到了
            bpf_probe_read_user_str(&string_p->buf[buf_off], MAX_STRING_SIZE, (void *)ptr);
        }
        save_str_to_buf(p.event, &string_p->buf[buf_off], next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    if (point_arg->type == TYPE_STRING_ARR && ptr != 0) {
        save_str_arr_to_buf(p.event, (const char *const *) ptr /*ptr*/, next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    if (point_arg->type == TYPE_POINTER && ptr != 0) {
        // 指针类型 通常读一下对应指针的数据即可 后续记得考虑兼容下32位
        
        // point_arg->alias_type
        // 某些成员是指针 有可能有必要再深入读取
        // 这个时候可以根据 alias_type 取出对应的参数配置 然后解析保存
        // 这个后面增补

        // 这是像 write 这样的函数中的 buf 参数 直接读取对应长度的数据即可
        if (point_arg->alias_type == TYPE_BUFFER_T) {
            // buffer 的单个元素长度就是 1 所以这里就是 read_count
            u32 read_len = read_count * 1;
            int status = save_bytes_to_buf(p.event, (void *)(ptr & 0xffffffffff), read_len, next_arg_index);
            if (status == 0) {
                buf_t *zero_p = get_buf(ZERO_BUF_IDX);
                if (zero_p == NULL) {
                    return next_arg_index;
                }
                save_bytes_to_buf(p.event, &zero_p->buf[0], read_len, next_arg_index);
                next_arg_index += 1;
            } else {
                next_arg_index += 1;
            }
            return next_arg_index;
        }
        // 读取指针所指向位置的值 并且保存
        u64 addr = 0;
        bpf_probe_read_user(&addr, sizeof(addr), (void*) ptr);
        save_to_submit_buf(p.event, (void *) &addr, sizeof(u64), next_arg_index);
        next_arg_index += 1;
        // 如果指向的是一个结构体 那么我们就再进一步把结构体数据读取出来
        if (addr == 0) {
            return next_arg_index;
        }
        u32 read_struct = 0;
        if (point_arg->alias_type == TYPE_PTHREAD_ATTR) {
            read_struct = 1;
        } else if (point_arg->alias_type == TYPE_IOVEC && read_count != 0) {
            // if (read_count > 6) {
            //     read_count = 6;
            // }
            // save_to_submit_buf(p.event, (void *)&read_count, sizeof(read_count), next_arg_index);
            // next_arg_index += 1;
            // for (int iov_index = 0; iov_index < read_count; iov_index++) {
            //     u64 iov_addr = addr + iov_index * 8 * 2;
            //     u64 iov_len = 0;
            //     u64 iov_base = 0;
            //     int errno = bpf_probe_read_user(&iov_len, sizeof(iov_len), (void*) iov_addr);
            //     errno = bpf_probe_read_user(&iov_base, sizeof(iov_base), (void*) (iov_addr + 8));
            //     if (errno == 0) {
            //         save_to_submit_buf(p.event, (void *)&iov_len, sizeof(iov_len), next_arg_index);
            //         next_arg_index += 1;
            //         save_to_submit_buf(p.event, (void *)&iov_base, sizeof(iov_base), next_arg_index);
            //         next_arg_index += 1;
            //         // 目前这样只是读取了第一个 iov 实际上要多次读取 数量是 iovcnt
            //         // 但是注意多个缓冲区并不是连续的
            //         // u32 read_len = read_count * iov_len;
            //         u32 read_len = iov_len;
            //         if (read_len > MAX_BUF_READ_SIZE) {
            //             read_len = MAX_BUF_READ_SIZE;
            //         }
            //         next_arg_index = save_bytes_with_len(p, iov_base, read_len, next_arg_index);
            //         return next_arg_index;
            //     }
            // }
            read_struct = 0;
        }
        if (read_struct == 1) {
            u32 struct_size = MAX_BYTES_ARR_SIZE;
            if (point_arg->size <= struct_size) {
                struct_size = point_arg->size;
            }
            // bpf_printk("[uprobe] struct_size:%d addr:0x%x\n", struct_size, addr);
            int status = save_bytes_to_buf(p.event, (void *)(addr & 0xffffffffff), struct_size, next_arg_index);
            if (status == 0) {
                buf_t *zero_p = get_buf(ZERO_BUF_IDX);
                if (zero_p == NULL) {
                    return next_arg_index;
                }
                save_bytes_to_buf(p.event, &zero_p->buf[0], struct_size, next_arg_index);
                next_arg_index += 1;
            } else {
                next_arg_index += 1;
            }
        }
        return next_arg_index;
    }
    if (point_arg->type == TYPE_STRUCT && ptr != 0) {
        // 结构体类型 直接读取对应大小的数据 具体转换交给前端
        u32 struct_size = MAX_BYTES_ARR_SIZE;
        if (point_arg->size <= struct_size) {
            struct_size = point_arg->size;
        }
        // 修复 MTE 读取可能不正常的情况
        int status = save_bytes_to_buf(p.event, (void *)(ptr & 0xffffffffff), struct_size, next_arg_index);
        if (status == 0) {
            // 保存失败的情况 比如 ptr 是一个非法的地址 ...
            buf_t *zero_p = get_buf(ZERO_BUF_IDX);
            if (zero_p == NULL) {
                return next_arg_index;
            }
            // 这个时候填充一个全0的内容进去 不然前端不好解析
            save_bytes_to_buf(p.event, &zero_p->buf[0], struct_size, next_arg_index);
            next_arg_index += 1;
        } else {
            next_arg_index += 1;
        }
        return next_arg_index;
    }
    return next_arg_index;
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

    args_t args = {};
    args.args[0] = READ_KERN(ctx->regs[0]);
    args.args[1] = READ_KERN(ctx->regs[1]);
    args.args[2] = READ_KERN(ctx->regs[2]);
    args.args[3] = READ_KERN(ctx->regs[3]);
    args.args[4] = READ_KERN(ctx->regs[4]);
    if (save_args(&args, UPROBE_ENTER) != 0) {
        return 0;
    };

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
    // #pragma unroll
    for (int i = 0; i < point_arg_count; i++) {
        // 先保存寄存器
        save_to_submit_buf(p.event, (void *)&args.args[i], sizeof(u64), next_arg_index);
        next_arg_index += 1;
        struct point_arg_t* point_arg = (struct point_arg_t*) &uprobe_point_args->point_args[i];
        if (point_arg->read_flag != UPROBE_ENTER_READ) {
            continue;
        }
        u32 read_count = MAX_BUF_READ_SIZE;
        if (point_arg->item_countindex >= 0) {
            u32 item_index = (u32) point_arg->item_countindex;
            if (item_index >= 6) {
                return 0;
            }
            u32 item_count = (u32) args.args[item_index];
            if (item_count <= read_count) {
                read_count = item_count;
            }
        }
        next_arg_index = read_arg(p, point_arg, args.args[i], read_count, next_arg_index);
    }
    // stackplz 的一个重要动作就是要取寄存器信息之类的
    // 所以除了 PERF_SAMPLE_RAW 还可能会有 PERF_SAMPLE_REGS_USER PERF_SAMPLE_STACK_USER
    // 经过实际测试 接收到的数据是结构体对齐的 但是最终对齐补了几位是无法预测的
    // 所以最后再保存一下这部分数据的大小
    u32 out_size = sizeof(event_context_t) + p.event->buf_off;
    save_to_submit_buf(p.event, (void *) &out_size, sizeof(u32), next_arg_index);
    events_perf_submit(&p, UPROBE_ENTER);
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
PROBE_STACK(8);
PROBE_STACK(9);
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