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

    if (size == 0)
        return 0;

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
    if (bpf_probe_read(&(event->args[event->buf_off + 1 + sizeof(int)]),
                       size & (MAX_BYTES_ARR_SIZE - 1),
                       ptr) == 0) {
        // We update buf_off only if all writes were successful
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
            bpf_printk("[syscall] 11 bpf_probe_read_user_str len:%d\n", sz);
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
        bpf_printk("[syscall] 22 bpf_probe_read_user_str len:%d\n", sz);
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