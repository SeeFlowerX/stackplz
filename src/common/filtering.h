#ifndef __FILTERING_H__
#define __FILTERING_H__

#include "vmlinux_510.h"
#include "maps.h"

static __always_inline u64 should_trace(program_data_t *p)
{

    u32 host_uid = bpf_get_current_uid_gid() & 0xffffffff;
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 host_pid = current_pid_tgid >> 32;
    u32 host_tid = current_pid_tgid & 0xffffffff;

    if (p->config->stackplz_pid == host_pid) {
        return 0;
    }

    u32 zero = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &zero);
    if (filter == NULL) {
        return 0;
    }

    if (filter->uid != MAGIC_UID && filter->uid != host_uid) {
        return 0;
    }
    if (filter->pid != MAGIC_PID && filter->pid != host_pid) {
        return 0;
    }
    if (filter->tid != MAGIC_TID && filter->tid != host_tid) {
        return 0;
    }

    return 1;
}

#endif