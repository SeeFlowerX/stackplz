#ifndef __FILTERING_H__
#define __FILTERING_H__

#include "vmlinux_510.h"
#include "maps.h"
#include "types.h"

static __always_inline u64 should_trace(program_data_t *p)
{

    config_entry_t *config = p->config;
    event_context_t *context = &p->event->context;

    u32 host_uid = bpf_get_current_uid_gid() & 0xffffffff;
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 host_pid = current_pid_tgid >> 32;
    u32 host_tid = current_pid_tgid & 0xffffffff;

    // 无论如何都必须把自己排除
    // 话说这里用 context.pid 应该更合理吧
    // 不过 tracee 是这样写的 暂且保持一致
    if (config->stackplz_pid == context->pid) {
        return 0;
    }

    // 线程名放在最前面
    u32* thread_name_flag = bpf_map_lookup_elem(&thread_filter, &p->event->context.comm);
    if (config->thread_whitelist == 1) {
        if (thread_name_flag == NULL) {
            return 0;
        }
    }
    if (thread_name_flag != NULL) {
        if (*thread_name_flag == THREAD_NAME_BLACKLIST) {
            return 0;
        }
        if (*thread_name_flag == THREAD_NAME_WHITELIST) {
            return 1;
        } 
    }

    // 黑名单优先 依次检查 thread_name tid pid uid trace_uid_group

    // context->tid [in] tid_blacklist return false, or skip
    u32 tid_blacklist_key = TID_BLACKLIST_START + context->tid;
    u32* tid_blacklist_value = bpf_map_lookup_elem(&common_list, &tid_blacklist_key);
    if (tid_blacklist_value != NULL) {
        return 0;
    }
    // context->tid [in] tid_whitelist return true, or skip
    u32 tid_whitelist_key = TID_WHITELIST_START + context->tid;
    u32* tid_whitelist_value = bpf_map_lookup_elem(&common_list, &tid_whitelist_key);
    if (tid_whitelist_value != NULL) {
        return 1;
    }
    // context->pid [in] pid_blacklist return false, or skip
    u32 pid_blacklist_key = PID_BLACKLIST_START + context->pid;
    u32* pid_blacklist_value = bpf_map_lookup_elem(&common_list, &pid_blacklist_key);
    if (pid_blacklist_value != NULL) {
        return 0;
    }
    // context->pid [in] pid_whitelist return true, or skip
    u32 pid_whitelist_key = PID_WHITELIST_START + context->pid;
    u32* pid_whitelist_value = bpf_map_lookup_elem(&common_list, &pid_whitelist_key);
    if (pid_whitelist_value != NULL) {
        return 1;
    }
    // context->pid [in] pid_forklist return true, or skip
    u32* pid_forklist_value = bpf_map_lookup_elem(&child_parent_map, &context->pid);
    if (pid_forklist_value != NULL) {
        return 1;
    }
    // context->uid [in] uid_blacklist return false, or skip
    u32 uid_blacklist_key = UID_BLACKLIST_START + context->uid;
    u32* uid_blacklist_value = bpf_map_lookup_elem(&common_list, &uid_blacklist_key);
    if (uid_blacklist_value != NULL) {
        return 0;
    }
    // context->uid [in] uid_whitelist return true, or skip
    u32 uid_whitelist_key = UID_WHITELIST_START + context->uid;
    u32* uid_whitelist_value = bpf_map_lookup_elem(&common_list, &uid_whitelist_key);
    if (uid_whitelist_value != NULL) {
        return 1;
    }

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }
    if (((filter->trace_uid_group & GROUP_ROOT) == GROUP_ROOT) && (context->uid == 0)) {
        return 1;
    }
    if (((filter->trace_uid_group & GROUP_SYSTEM) == GROUP_SYSTEM) && (context->uid == 1000)) {
        return 1;
    }
    if (((filter->trace_uid_group & GROUP_SHELL) == GROUP_SHELL) && (context->uid == 2000)) {
        return 1;
    }
    if (((filter->trace_uid_group & GROUP_APP) == GROUP_APP) && (context->uid >= 10000) && (context->uid <= 19999)) {
        return 1;
    }
    if (((filter->trace_uid_group & GROUP_ISO) == GROUP_ISO) && (context->uid >= 99000) && (context->uid <= 99999)) {
        return 1;
    }

    return 0;
}

#endif