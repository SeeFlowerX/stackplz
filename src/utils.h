#ifndef STACKPLZ_UTILS_H
#define STACKPLZ_UTILS_H

#include "vmlinux_510.h"

#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

#include "common/common.h"
#include "common/consts.h"
#include "common/buffer.h"

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

// 使用 __noinline 一定程度上可以提升循环次数
// 不过增加循环次数的时候 验证器耗时也会增加
static __noinline u32 read_args(program_data_t* p, point_args_t* point_args, op_ctx_t* op_ctx, ctx_regs_t *ctx_regs) {
    int zero = 0;
    // op_config_t* op = NULL;
    op_config_t* op = bpf_map_lookup_elem(&op_list, &zero);
    u32 maxop = MAX_OP_COUNT;
    // u32 maxop = point_args->max_op_count;
    // if (maxop > MAX_OP_COUNT) {
    //     maxop = MAX_OP_COUNT;
    // }
    for (int i = 0; i < maxop; i++) {
        if (op != NULL && op_ctx->post_code != OP_SKIP) {
            op_ctx->op_code = op_ctx->post_code;
            op_ctx->post_code = OP_SKIP;
        } else {
            if (op_ctx->op_key_index >= MAX_OP_COUNT) return 0;
            u32 op_key = point_args->op_key_list[op_ctx->op_key_index];
            op = bpf_map_lookup_elem(&op_list, &op_key);
            if (unlikely(op == NULL)) return 0;
            op_ctx->op_code = op->code;
            op_ctx->post_code = op->post_code;
            op_ctx->op_key_index += 1;
        }
        if (op_ctx->op_code == OP_SKIP) break;
        switch (op_ctx->op_code) {
            case OP_RESET_CTX:
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
                break;
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
            case OP_FOR_BREAK:
                if (op_ctx->loop_count == 0) {
                    op_ctx->loop_index = op_ctx->op_key_index;
                }
                if (op_ctx->loop_count >= op_ctx->break_count) {
                    op_ctx->loop_count = 0;
                    op_ctx->break_count = 0;
                    op_ctx->loop_index = 0;
                } else {
                    op_ctx->loop_count += 1;
                    op_ctx->op_key_index = op_ctx->loop_index;
                }
                break;
            case OP_SET_BREAK_COUNT:
                op_ctx->break_count = MAX_LOOP_COUNT;
                if (op_ctx->break_count > op->value) {
                    op_ctx->break_count = op->value;
                }
                break;
            case OP_SET_BREAK_COUNT_REG_VALUE:
                op_ctx->break_count = MAX_LOOP_COUNT;
                if (op_ctx->break_count > op_ctx->reg_value) {
                    op_ctx->break_count = op_ctx->reg_value;
                }
                break;
            case OP_SET_BREAK_COUNT_POINTER_VALUE:
                op_ctx->break_count = MAX_LOOP_COUNT;
                if (op_ctx->break_count > op_ctx->pointer_value) {
                    op_ctx->break_count = op_ctx->pointer_value;
                }
                break;
            case OP_SAVE_ADDR:
                save_to_submit_buf(p->event, (void *)&op_ctx->read_addr, sizeof(op_ctx->read_addr), op_ctx->save_index);
                op_ctx->save_index += 1;
                break;
            case OP_ADD_REG:
                op_ctx->read_addr += op_ctx->reg_value;
                break;
            case OP_SUB_REG:
                op_ctx->read_addr -= op_ctx->reg_value;
                break;
            case OP_READ_REG:
                if (op->pre_code == OP_SET_REG_INDEX) {
                    op_ctx->reg_index = op->value;
                }
                // make ebpf verifier happy
                if (op_ctx->reg_index >= REG_ARM64_MAX) {
                    return 0;
                }
                if (op_ctx->reg_index == 0) {
                    op_ctx->reg_value = op_ctx->reg_0;
                } else {
                    op_ctx->reg_value = READ_KERN(ctx_regs->regs[op_ctx->reg_index]);
                }
                break;
            case OP_SAVE_REG:
                save_to_submit_buf(p->event, (void *)&op_ctx->reg_value, sizeof(op_ctx->reg_value), op_ctx->save_index);
                op_ctx->save_index += 1;
                break;
            case OP_READ_POINTER:
                if (op->pre_code == OP_ADD_OFFSET) {
                    bpf_probe_read_user(&op_ctx->pointer_value, sizeof(op_ctx->pointer_value), (void*)(op_ctx->read_addr + op->value));
                } else if (op->pre_code == OP_SUB_OFFSET) {
                    bpf_probe_read_user(&op_ctx->pointer_value, sizeof(op_ctx->pointer_value), (void*)(op_ctx->read_addr - op->value));
                } else {
                    bpf_probe_read_user(&op_ctx->pointer_value, sizeof(op_ctx->pointer_value), (void*)op_ctx->read_addr);
                }
                break;
            case OP_SAVE_POINTER:
                save_to_submit_buf(p->event, (void *)&op_ctx->pointer_value, sizeof(op_ctx->pointer_value), op_ctx->save_index);
                op_ctx->save_index += 1;
                break;
            case OP_SAVE_STRUCT:
                // fix memory tag
                op_ctx->read_addr = op_ctx->read_addr & 0xffffffffffff;
                if (op->pre_code == OP_SET_READ_COUNT) {
                    op_ctx->read_len *= op->value;
                }
                if (op_ctx->read_len > MAX_BYTES_ARR_SIZE) {
                    op_ctx->read_len = MAX_BYTES_ARR_SIZE;
                }
                int save_struct_status = save_bytes_to_buf(p->event, (void *)(op_ctx->read_addr), op_ctx->read_len, op_ctx->save_index);
                if (save_struct_status == 0) {
                    // 保存失败的情况 比如是一个非法的地址 那么就填一个空的 buf
                    // 那么只会保存 save_index 和 size -> [save_index][size][]
                    // ? 这里的处理方法好像不对 应该没问题 因为失败的时候 buf_off 没有变化
                    save_bytes_to_buf(p->event, 0, 0, op_ctx->save_index);
                }
                op_ctx->save_index += 1;
                break;
            case OP_FILTER_VALUE: {
                // 配合 OP_READ_REG 比较寄存器的值是否匹配
                arg_filter_t* filter = bpf_map_lookup_elem(&arg_filter, &op->value);
                if (unlikely(filter == NULL)) return 0;
                if (filter->filter_type == EQUAL_FILTER) {
                    if (filter->num_val != op_ctx->reg_value) {
                        op_ctx->match_blacklist = 1;
                    }
                } else if (filter->filter_type == GREATER_FILTER) {
                    if (filter->num_val <= op_ctx->reg_value) {
                        op_ctx->match_blacklist = 1;
                    }
                } else if (filter->filter_type == LESS_FILTER) {
                    if (filter->num_val >= op_ctx->reg_value) {
                        op_ctx->match_blacklist = 1;
                    }
                }
                break;
            }
            case OP_FILTER_BUFFER: {
                arg_filter_t* filter = bpf_map_lookup_elem(&arg_filter, &op->value);
                if (unlikely(filter == NULL)) return 0;
                if (filter->filter_type == WHITELIST_FILTER) {
                    op_ctx->apply_filter = 1;
                    // 等同于读取8个字节 过滤8字节基本上够用了
                    u64 ptr = op_ctx->read_addr & 0xffffffffffff;
                    bpf_probe_read_user(&ptr, sizeof(ptr), (void*) ptr);
                    // str_len = (8 - 要比较的字节数) * 8
                    if (filter->num_val == (ptr & (0xffffffffffffffff >> filter->str_len))) {
                        op_ctx->match_whitelist = 1;
                    }
                }
                break;
            }
            case OP_FILTER_STRING: {
                // 这里会受到循环次数的限制
                // 实测 384 可以 512 不行 除非有什么更好的优化方法
                arg_filter_t* filter = bpf_map_lookup_elem(&arg_filter, &op->value);
                if (unlikely(filter == NULL)) return 0;
                bool is_match = strcmp_by_map(op_ctx, filter);
                if (filter->filter_type == WHITELIST_FILTER) {
                    op_ctx->apply_filter = 1;
                    if (is_match) {
                        op_ctx->match_whitelist = 1;
                    }
                } else if (filter->filter_type == BLACKLIST_FILTER && is_match) {
                    op_ctx->match_blacklist = 1;
                }
                break;
            }
            case OP_SAVE_STRING:
                // fix memory tag
                op_ctx->read_addr = op_ctx->read_addr & 0xffffffffffff;
                u32 old_off = p->event->buf_off;
                int save_string_status = save_str_to_buf(p->event, (void*) op_ctx->read_addr, op_ctx->save_index);
                if (save_string_status == 0) {
                    // 失败的情况存一个空数据 暂时没有遇到 有待测试
                    save_bytes_to_buf(p->event, 0, 0, op_ctx->save_index);
                } else {
                   op_ctx->str_len = p->event->buf_off - (old_off + sizeof(int) + 1);
                }
                op_ctx->save_index += 1;
                break;
            case OP_SAVE_PTR_STRING:
            {
                u64 ptr = op_ctx->read_addr & 0xffffffffffff;
                bpf_probe_read_user(&ptr, sizeof(ptr), (void*) ptr);
                save_to_submit_buf(p->event, (void *)&ptr, sizeof(ptr), op_ctx->save_index);
                op_ctx->save_index += 1;
                // 每次取出后使用前都要 fix 很坑
                ptr = ptr & 0xffffffffffff;
                int status = save_str_to_buf(p->event, (void*) ptr, op_ctx->save_index);
                if (status == 0) {
                    // save_str_to_buf 中应当将 bpf_probe_read_str 返回 0 时视为字符串为空
                    // 地址异常时 bpf_probe_read_str 返回为负数 此时将认为字符串数组读取结束
                    // 这里需要为字符串数组的读取设定一个标志 和空字符串的情况区分开
                    save_bytes_to_buf(p->event, 0, STRARR_MAGIC_LEN, op_ctx->save_index);
                    // 为读取字符串数组设计的
                    op_ctx->loop_count = op_ctx->break_count;
                }
                op_ctx->save_index += 1;
                break;
            }
            case OP_READ_STD_STRING:
            {
                // 搭配 OP_SAVE_STRING 使用 这里仅计算实际的字符串地址
                u64 ptr = op_ctx->read_addr & 0xffffffffffff;
                u8 value;
                bpf_probe_read_user(&value, sizeof(value), (void*) ptr);
                if ((value & 1) == 0) {
                    ptr += 1;
                } else {
                    ptr += 8 * 2;
                    bpf_probe_read_user(&ptr, sizeof(ptr), (void*) ptr);
                }
                op_ctx->read_addr = ptr;
                break;
            }
            default:
                break;
        }
        // 黑名单不用读完 直接结束
        if (op_ctx->match_blacklist == 1) break;
    }

    // 跳过逻辑：
    // 1. 与任意黑名单规则之一匹配，跳过
    // 2. 不与任何白名单规则匹配，跳过
    if (op_ctx->match_blacklist == 1) {
        op_ctx->skip_flag = 1;
        return 0;
    }
    if (op_ctx->apply_filter == 1 && op_ctx->match_whitelist == 0) {
        op_ctx->skip_flag = 1;
    }

    return 0;
}

char __license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

#endif
