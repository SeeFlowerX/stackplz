#include "bpf/bpf_helpers.h"

#include "maps.h"
#include "types.h"

#define barrier()		asm volatile("" ::: "memory")

static __always_inline buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

// The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)

static __always_inline int save_to_submit_buf(event_data_t *event, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][ ... buffer[size] ... ]

    if (size == 0)
        return 0;

    barrier();
    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    event->args[event->buf_off] = index;

    // Satisfy verifier
    if (event->buf_off > ARGS_BUF_SIZE - (MAX_ELEMENT_SIZE + 1))
        return 0;

    // Read into buffer
    if (bpf_probe_read(&(event->args[event->buf_off + 1]), size, ptr) == 0) {
        // We update buf_off only if all writes were successful
        event->buf_off += size + 1;
        event->context.argnum++;
        return 1;
    }

    return 0;
}

static __always_inline int save_bytes_to_buf(event_data_t *event, void *ptr, u32 size, u8 index)
{
    // Data saved to submit buf: [index][size][ ... bytes ... ]

    // if (size == 0)
    //     return 0;

    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    event->args[event->buf_off] = index;

    if (event->buf_off > ARGS_BUF_SIZE - (sizeof(int) + 1))
        return 0;

    // Save size to buffer
    if (bpf_probe_read(&(event->args[event->buf_off + 1]), sizeof(int), &size) != 0) {
        return 0;
    }

    if (event->buf_off > ARGS_BUF_SIZE - (MAX_BYTES_ARR_SIZE + 1 + sizeof(int)))
        return 0;

    // Read bytes into buffer
    if (size > 0) {
        if (bpf_probe_read(&(event->args[event->buf_off + 1 + sizeof(int)]),
                        size & (MAX_BYTES_ARR_SIZE - 1),
                        ptr) == 0) {
            // We update buf_off only if all writes were successful
            event->buf_off += size + 1 + sizeof(int);
            event->context.argnum++;
            return 1;
        }
    } else {
        event->buf_off += size + 1 + sizeof(int);
        event->context.argnum++;
        return 1;
    }

    return 0;
}

// #define MAX_STR_ARR_ELEM      38
#define MAX_STR_ARR_ELEM      128
#define __user

static __always_inline int save_str_arr_to_buf(event_data_t *event, const char __user *const __user *ptr, u8 index) {
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;

    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    event->args[event->buf_off] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = event->buf_off + 1;
    event->buf_off += 2;

#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz =
            bpf_probe_read_user_str(&(event->args[event->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (event->buf_off > ARGS_BUF_SIZE - sizeof(int))
                // Satisfy validator
                goto out;
            // bpf_probe_read_user(&(event->args[event->buf_off]), sizeof(int), &sz);
            __builtin_memcpy(&(event->args[event->buf_off]), &sz, sizeof(int));
            event->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (event->buf_off > ARGS_BUF_SIZE - MAX_STRING_SIZE - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz =
        bpf_probe_read_user_str(&(event->args[event->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (event->buf_off > ARGS_BUF_SIZE - sizeof(int))
            // Satisfy validator
            goto out;
        // bpf_probe_read_user(&(event->args[event->buf_off]), sizeof(int), &sz);
        __builtin_memcpy(&(event->args[event->buf_off]), &sz, sizeof(int));
        event->buf_off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    if (orig_off > ARGS_BUF_SIZE - 1)
        return 0;
    event->args[orig_off] = elem_num;
    event->context.argnum++;
    return 1;
}


static __always_inline int save_str_to_buf(event_data_t *event, void *ptr, u8 index)
{
    // Data saved to submit buf: [index][size][ ... string ... ]

    if (event->buf_off > ARGS_BUF_SIZE - 1)
        return 0;

    // Save argument index
    event->args[event->buf_off] = index;

    // Satisfy verifier for probe read
    if (event->buf_off > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
        return 0;

    // Read into buffer
    int sz =
        bpf_probe_read_str(&(event->args[event->buf_off + 1 + sizeof(int)]), MAX_STRING_SIZE, ptr);
    if (sz > 0) {
        barrier();
        // Satisfy verifier for probe read
        if (event->buf_off > ARGS_BUF_SIZE - (MAX_STRING_SIZE + 1 + sizeof(int)))
            return 0;

        __builtin_memcpy(&(event->args[event->buf_off + 1]), &sz, sizeof(int));
        event->buf_off += sz + sizeof(int) + 1;
        event->context.argnum++;
        return 1;
    }

    return 0;
}


static __always_inline int events_perf_submit(program_data_t *p, u32 id)
{
    p->event->context.eventid = id;

    u32 size = sizeof(event_context_t) + p->event->buf_off;

    // inline bounds check to force compiler to use the register of size
    asm volatile("if %[size] < %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n"
                 :
                 : [size] "r"(size), [max_size] "i"(MAX_EVENT_SIZE));

    return bpf_perf_event_output(p->ctx, &events, BPF_F_CURRENT_CPU, p->event, size);
}

static __always_inline str_buf_t *make_str_buf() {
    u32 zero = 0;
    struct str_buf_t *gen_key = bpf_map_lookup_elem(&str_buf_gen, &zero);
    if (gen_key == NULL) return NULL;
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&str_buf_map, &id, gen_key, BPF_ANY);
    return bpf_map_lookup_elem(&str_buf_map, &id);
}

static __always_inline u32 strcmp_by_map(arg_filter_t *filter_config, buf_t *string_p) {
    u32 str_len = 256;
    if (str_len > filter_config->oldstr_len) {
        str_len = filter_config->oldstr_len;
    }
    str_buf_t* str_value = make_str_buf();
    if (str_value == NULL) {
        return 0;
    }
    if (str_len > 0) {
        // 必须重置
        __builtin_memset(str_value->str_val, 0, sizeof(str_value->str_val));
        bpf_probe_read(str_value->str_val, str_len, string_p->buf);
    }
    // map的key最好是一个不变的内容 否则会引起一些奇怪的冲突
    bpf_map_update_elem(&str_buf, &filter_config->oldstr_val, &str_len, BPF_ANY);
    u32* str_len_value = bpf_map_lookup_elem(&str_buf, str_value);

    if (str_len_value == NULL) {
        return 0;
    }
    bpf_map_delete_elem(&str_buf, str_value);
    return 1;
}

static __always_inline u32 next_strcmp_by_map(op_ctx_t* op_ctx, next_arg_filter_t *filter) {
    str_buf_t* str_value = make_str_buf();
    if (unlikely(str_value == NULL)) return 0;
    __builtin_memset(str_value->str_val, 0, sizeof(str_value->str_val));
    // 读取的字符串长度小于过滤规则预设的字符串长度 那就没有比较的必要了
    if (op_ctx->str_len < filter->str_len) {
        return 0;
    }
    // 进入这里说明读取的字符串长度大于或者等于预设规则的字符串长度
    // 那么只要从字符串的地址再次读取预设规则的长度即可
    u32 read_str_len = filter->str_len;
    // 过验证器用 更新预设规则的 map 前会确保长度小于 MAX_STRCMP_LEN
    if (read_str_len > MAX_STRCMP_LEN) {
        read_str_len = MAX_STRCMP_LEN;
    }
    bpf_probe_read(str_value->str_val, read_str_len, (void*) op_ctx->read_addr);
    // map的key最好是一个不变的内容 否则会引起一些奇怪的冲突
    // 将预设规则的字符串更新到读取结果更新到 read_str_len 其实就是预设规则字符串长度
    bpf_map_update_elem(&str_buf, filter->str_val, &read_str_len, BPF_ANY);
    // 将字符串读取结果作为 key 从 map 中取值
    // 取到了那就是匹配了 没取到则不匹配
    if (bpf_map_lookup_elem(&str_buf, str_value) == NULL) {
        bpf_map_delete_elem(&str_buf, filter->str_val);
        return 0;
    }
    bpf_map_delete_elem(&str_buf, filter->str_val);
    return 1;
}