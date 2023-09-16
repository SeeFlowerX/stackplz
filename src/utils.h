#ifndef STACKPLZ_UTILS_H
#define STACKPLZ_UTILS_H

#include "vmlinux_510.h"

#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

#include "common/common.h"
#include "common/consts.h"
#include "common/buffer.h"

#define MAX_POINT_ARG_COUNT 10

#define FILTER_INDEX_NONE 0x0
#define FILTER_INDEX_SKIP 0x1234

typedef struct point_arg_t {
    u32 point_flag;
    u32 filter_idx[MAX_FILTER_COUNT];
    u32 read_index;
	u32 read_offset;
    u32 base_type;
    u32 alias_type;
    u32 read_count;
	u32 item_persize;
	u32 item_countindex;
	u32 tmp_index;
} point_arg;

static __always_inline match_ctx_t *make_match_ctx() {
    u32 zero = 0;
    struct match_ctx_t *match_ctx = bpf_map_lookup_elem(&match_ctx_gen, &zero);
    if (match_ctx == NULL) return NULL;
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&match_ctx_map, &id, match_ctx, BPF_ANY);
    return bpf_map_lookup_elem(&match_ctx_map, &id);
}

static __always_inline u32 get_read_count(struct pt_regs* ctx, struct point_arg_t* point_arg) {
    // 以寄存器值作为读取大小 只包含 x0-x28 fp寄存器就是x29 所以不包含在内
    // 或者以预设 read_count 作为读取大小
    // 这里还可以改进一下 read_count 本身有上限 可以设为一个大于上限的值
    // 即先比较 发现大于上限 那么减去特定值 作为 item_countindex
    // 这样可以实际省去 item_countindex
    u32 read_count = 0;
    if (point_arg->item_countindex >= REG_ARM64_X0 && point_arg->item_countindex < REG_ARM64_X29) {
        read_count = READ_KERN(ctx->regs[point_arg->item_countindex]);
    } else {
        read_count = point_arg->read_count;
    }
    return read_count * point_arg->item_persize;
}

static __always_inline u64 get_arg_ptr(struct pt_regs* ctx, struct point_arg_t* point_arg, int arg_index, u64 reg_0) {
    // REG_ARM64_MAX 意味着需要跳过 但在调用本函数前就应该进行判断
    // REG_ARM64_ABS 意味着 read_offset 作为 绝对地址 用于后续读取
    // REG_ARM64_X0 有关的比较是因为 sys_exit 完成后要读取执行前的寄存器
    u64 ptr = point_arg->read_offset;
    if (point_arg->read_index == REG_ARM64_ABS) {
        /* return ptr; */
    } else if (point_arg->read_index == REG_ARM64_INDEX) {
        if (arg_index == REG_ARM64_X0) {
            ptr += reg_0;
        } else if (arg_index <= REG_ARM64_LR) {
            ptr += READ_KERN(ctx->regs[arg_index]);
        } else {
            ptr = 0; // never
        }
    } else if (point_arg->read_index == REG_ARM64_MAX) {
        ptr = 0; // never
    } else if (point_arg->read_index == REG_ARM64_PC) {
        ptr += READ_KERN(ctx->pc);
    } else if (point_arg->read_index == REG_ARM64_SP) {
        ptr += READ_KERN(ctx->sp);
    } else if (point_arg->read_index <= REG_ARM64_LR) {
        if (point_arg->read_index == REG_ARM64_X0) {
            ptr += reg_0;
        } else {
            ptr += READ_KERN(ctx->regs[point_arg->read_index]);
        }
    } else {
        ptr = 0; // never
    }
    return ptr;
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

static __always_inline u32 read_ptr_arg(program_data_t p, struct point_arg_t* point_arg, u64 ptr, u32 read_count, u32 next_arg_index) {
    // 这些都是常规的 指针 + 结构体 按照读取结构体的方式读取即可
    if (point_arg->alias_type == TYPE_PTHREAD_ATTR) {
        // 结构体类型 直接读取对应大小的数据 具体转换交给前端
        u32 struct_size = MAX_BYTES_ARR_SIZE;
        if (point_arg->read_count <= struct_size) {
            struct_size = point_arg->read_count;
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
    // 比较复杂的 指针 + 结构体
    if (point_arg->alias_type == TYPE_IOVEC) {
        struct iovec iovec_ptr;
        int errno = bpf_probe_read_user(&iovec_ptr, sizeof(iovec_ptr), (void*) ptr);
        if (errno == 0) {
            save_to_submit_buf(p.event, (void *)&iovec_ptr, sizeof(iovec_ptr), next_arg_index);
            next_arg_index += 1;
            // 目前这样只是读取了第一个 iov 实际上要多次读取 数量是 iovcnt
            // 但是注意多个缓冲区并不是连续的
            u64 iov_base = (u64)iovec_ptr.iov_base;
            u32 iov_len = (u64)iovec_ptr.iov_len;
            // u32 read_len = read_count * iov_len;
            u32 read_len = iov_len;
            if (read_len > MAX_BUF_READ_SIZE) {
                read_len = MAX_BUF_READ_SIZE;
            }
            next_arg_index = save_bytes_with_len(p, iov_base, read_len, next_arg_index);
            return next_arg_index;
        }
    }
    return next_arg_index;
}

static __always_inline u32 read_arg(program_data_t p, struct point_arg_t* point_arg, u64 ptr, u32 read_count, u32 next_arg_index) {
    point_arg->tmp_index = FILTER_INDEX_NONE;
    if (ptr == 0) {
        return next_arg_index;
    }

    if (point_arg->base_type == TYPE_POINTER) {
        // 指针类型 通常读一下对应指针的数据即可 后续记得考虑兼容下32位
        // 读取指针所指向位置的值 并且保存
        u64 addr = 0;
        bpf_probe_read_user(&addr, sizeof(addr), (void*) ptr);
        save_to_submit_buf(p.event, (void *) &addr, sizeof(u64), next_arg_index);
        next_arg_index += 1;
        if (addr == 0) {
            return next_arg_index;
        }
        // 指针的指针 暂时没有这个需求
        // next_arg_index = read_ptr_arg(p, point_arg, addr, read_count, next_arg_index);
        return next_arg_index;
    }
    if (point_arg->base_type == TYPE_NONE) {
        return next_arg_index;
    }
    if (point_arg->base_type == TYPE_NUM) {
        // 这种具体类型转换交给前端做
        return next_arg_index;
    }
    if (point_arg->base_type == TYPE_STRING) {
        u32 buf_off = 0;
        buf_t *string_p = get_buf(STRING_BUF_IDX);
        if (string_p == NULL) {
            return next_arg_index;
        }
        __builtin_memset((void *) string_p, 0, sizeof(string_p));
        int status = bpf_probe_read_user(&string_p->buf[buf_off], MAX_STRING_SIZE, (void *)ptr);
        if (status < 0) {
            // MTE 其实也正常读取到了
            bpf_probe_read_user_str(&string_p->buf[buf_off], MAX_STRING_SIZE, (void *)ptr);
        }
        // Q: 这里为什么不直接定义变量呢
        // A: 经过测试，发现直接定义变量 + 循环中赋值 + 循环中/外比较 => 会导致 argument list too long
        // A: 但是从map中拿一个结构体出来不会受到影响，要注意的是记得每次重置结构体内容
        match_ctx_t* match_ctx = make_match_ctx();
        if (match_ctx == NULL) {
            return next_arg_index;
        }
        match_ctx->apply_filter = 0;
        match_ctx->match_blacklist = 0;
        match_ctx->match_whitelist = 0;
        for (int j = 0; j < MAX_FILTER_COUNT; j++) {
            u32 filter_idx = point_arg->filter_idx[j];
            if (filter_idx != FILTER_INDEX_NONE) {
                match_ctx->apply_filter = 1;
                arg_filter_t* filter_config = bpf_map_lookup_elem(&arg_filter, &filter_idx);
                // 按照设计这里必须不为NULL
                if (filter_config == NULL) {
                    return next_arg_index;
                }
                // 借助map来比较字符串：
                // 1. 将读已经取到的字符串复制filter_config预设长度的内容到临时变量字符串
                // 2. 将该临时变量字符串作为key，字符串长度作为value更新到map中
                // 3. 以filter_config预设的字符串作为key，从map中取出值
                // 4. 能取到说明两个字符串相同，否则不匹配
                u32 startswith = strcmp_by_map(filter_config, string_p);
                if (filter_config->filter_type == WHITELIST_FILTER && startswith == 1){
                    match_ctx->match_whitelist = 1;
                } else if (filter_config->filter_type == BLACKLIST_FILTER && startswith == 1){
                    match_ctx->match_blacklist = 1;
                } else if (filter_config->filter_type == REPLACE_FILTER && startswith == 1){
                    // 将替换的参数 视作白名单处理
                    match_ctx->match_whitelist = 1;
                    // replace 是替换内容的操作 实际上不影响过滤
                    // 这里注意写入有一个截断符 由用户态完成处理 实际上让长度+1即可
                    // u32 str_len = 256;
                    // if (str_len > filter_config->newstr_len) {
                    //     str_len = filter_config->newstr_len;
                    // }
                    // 经过测试 bpf_probe_write_user 的 len 参数不能是动态的
                    // 即使通过 if 设定一个上限也不行
                    int write_status = bpf_probe_write_user((void *)(ptr & 0xffffffffff), filter_config->newstr_val, sizeof(filter_config->newstr_val));
                    // bpf_printk("[syscall] ptr:0x%lx status:%d filter_index:%d\n", ptr, write_status, filter_config->filter_index);
                    // bpf_printk("[syscall] ptr:0x%lx old:%s\n", ptr, filter_config->newstr_val);
                    // bpf_printk("[syscall] ptr:0x%lx new:%s\n", ptr, string_p->buf);
                }
            }
        }
        // 跳过逻辑：
        // 1. 不与任何白名单规则匹配，跳过
        // 2. 与任意黑名单规则之一匹配，跳过
        if (match_ctx->apply_filter == 1) {
            if (match_ctx->match_whitelist == 0 || match_ctx->match_blacklist == 1) {
                point_arg->tmp_index = FILTER_INDEX_SKIP;
                return next_arg_index;
            }
        }
        save_str_to_buf(p.event, &string_p->buf[buf_off], next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    if (point_arg->base_type == TYPE_STRING_ARR) {
        save_str_arr_to_buf(p.event, (const char *const *) ptr /*ptr*/, next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    if (point_arg->base_type == TYPE_STRUCT || point_arg->base_type == TYPE_ARRAY) {
        // 结构体类型 直接读取对应大小的数据 具体转换交给前端
        u32 max_read_len = MAX_BYTES_ARR_SIZE;
        if (read_count <= max_read_len) {
            max_read_len = read_count;
        }
        // 修复 MTE 读取可能不正常的情况
        int status = save_bytes_to_buf(p.event, (void *)(ptr & 0xffffffffff), max_read_len, next_arg_index);
        if (status == 0) {
            // 保存失败的情况 比如 ptr 是一个非法的地址 ...
            buf_t *zero_p = get_buf(ZERO_BUF_IDX);
            if (zero_p == NULL) {
                return next_arg_index;
            }
            // 这个时候填充一个全0的内容进去 不然前端不好解析
            save_bytes_to_buf(p.event, &zero_p->buf[0], max_read_len, next_arg_index);
            next_arg_index += 1;
        } else {
            next_arg_index += 1;
        }
        return next_arg_index;
    }
    return next_arg_index;
}

char __license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

#endif
