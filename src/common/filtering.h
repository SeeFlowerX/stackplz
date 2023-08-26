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

    // 要考虑到用户使用不同的方法去指示要追踪的进程
    // 所以过滤的写法不能简单根据 uid/pid/tid 来做
    // 考虑下面的场景
    // 1. 用户有可能指定 uid/pid/tid 中的一个或者多个
    // 2. 用户可能在上一轮 trace 之后 决定对某个特定的 tid 进行追踪
    // 3. 用户可能希望追踪单个进程 但是这个进程可能会产生新的进程
    // 4. 用户可能希望追踪所属uid下的全部进程以及另外一个特定进程 要注意某些特定uid下有很多进程
    // 判断是否追踪的逻辑设计如下
    // 1. 按照 uid pid tid 的次序判断是否需要追踪
    // 2. 出现满足条件的情况 不再进行后续判断
    // 3. 出现不满足的情况 继续判断下一项
    // 4. 在ebpf程序中维护有数量上限的 uid/pid/tid 列表 即它们不被限制为单个
    // 5. tid 不具有唯一性 必须搭配 pid

    // 仔细想了下上面的逻辑要同时实现不太可能 还是按这样来？
    // 1. 只追踪uid所属进程；同时支持
    //     1. pid黑名单列表
    //     2. tid黑名单列表（其实不同pid下存在相同tid的概率很小，加上这里是黑名单，所以黑名单同时生效，不需要组合pid+tid）
    //     3. 线程名黑名单（这是为了忽略掉某些实际上不关心且过于活跃的线程）
    // 2. 只追踪指定pid进程，以及产生的子进程（可不选）；同时支持
    //     1. tid黑名单列表
    //     2. 线程名黑名单
    // 3. 只追踪pid+tid限定的线程
    
    // 额外的支持
    // 1. 可指定一个或者多个pid
    // 2. 可指定一个pid+多个tid

    // 上面的情况，都应该只能以其中一种模式进行过滤
    // 考虑到指明了过滤模式 那么就不需要使用 MAGIC_PID 去判断了 因为对应的模式下对应参数必须有值

    // 线程名放在最前面
    u32* thread_name_flag = bpf_map_lookup_elem(&thread_filter, &p->event->context.comm);
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