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