#ifndef __EVENT_INIT_H__
#define __EVENT_INIT_H__

#include "vmlinux_510.h"

#include "bpf_helpers.h"
#include "common/common.h"
#include <common/task.h>
#include "common/consts.h"
#include "types.h"
#include "maps.h"

static __always_inline int
init_context(void *ctx, event_context_t *context, struct task_struct *task)
{
    long ret = 0;
    u64 id = bpf_get_current_pid_tgid();
    context->host_tid = id;
    context->host_pid = id >> 32;
    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->uid = bpf_get_current_uid_gid();

    __builtin_memset(context->comm, 0, sizeof(context->comm));
    ret = bpf_get_current_comm(&context->comm, sizeof(context->comm));
    if (unlikely(ret < 0)) {
        return -1;
    }

    context->ts = bpf_ktime_get_ns();
    context->argnum = 0;

    return 0;
}

// clang-format off
static __always_inline int init_program_data(program_data_t *p, void *ctx)
{
    long ret = 0;
    int zero = 0;

    // allow caller to specify a stack/map based event_data_t pointer
    if (p->event == NULL) {
        p->event = bpf_map_lookup_elem(&event_data_map, &zero);
        if (unlikely(p->event == NULL))
            return 0;
    }

    p->config = bpf_map_lookup_elem(&base_config, &zero);
    if (unlikely(p->config == NULL))
        return 0;

    p->event->task = (struct task_struct *) bpf_get_current_task();
    ret = init_context(ctx, &p->event->context, p->event->task);
    if (unlikely(ret < 0)) {
        // disable logging as a workaround for instruction limit verifier error on kernel 4.19
        // tracee_log(ctx, BPF_LOG_LVL_ERROR, BPF_LOG_ID_INIT_CONTEXT, ret);
        return 0;
    }

    p->ctx = ctx;
    p->event->buf_off = 0;

    return 1;
}

#endif