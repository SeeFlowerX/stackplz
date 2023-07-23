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

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    if (config->filter_mode == UID_MODE) {
        if (filter->uid == context->uid) {
            for (int i = 0; i < MAX_COUNT; i++) {
                // 因为列表肯定是挨着填充的 所以遇到 MAGIC 就可以直接结束循环了
                if (filter->blacklist_pids[i] == MAGIC_PID) break;
                if (filter->blacklist_pids[i] == context->pid) {
                    return 0;
                };
            }
            for (int i = 0; i < MAX_COUNT; i++) {
                if (filter->blacklist_tids[i] == MAGIC_TID) break;
                if (filter->blacklist_tids[i] == context->tid) {
                    return 0;
                };
            }
            // 这样过滤很方便 思路打开 简而言之就是不要自己维护列表 直接把 map 当列表用最方便
            // 即直接用 黑/白名单 作为key 然后 value 作为 flag 后面也可以改进 uid pid 
            u32 *flag = bpf_map_lookup_elem(&thread_filter, &p->event->context.comm);
            if (filter->thread_name_whitelist == 1) {
                if (flag != NULL && *flag == 2) {
                    return 1;
                }
                return 0;
            }
            if (flag != NULL && *flag == 1) {
                return 0;
            }

            return 1;
        }
        return 0;
    } else if (config->filter_mode == PID_MODE) {
        if (filter->pid == context->pid) {
            for (int i = 0; i < MAX_COUNT; i++) {
                if (filter->blacklist_tids[i] == MAGIC_TID) break;
                if (filter->blacklist_tids[i] == context->tid) {
                    return 0;
                };
            }
            u32 *flag = bpf_map_lookup_elem(&thread_filter, &p->event->context.comm);
            if (filter->thread_name_whitelist == 1) {
                if (flag != NULL && *flag == 2) {
                    return 1;
                }
                return 0;
            }
            if (flag != NULL && *flag == 1) {
                return 0;
            }
            return 1;
        }
        return 0;
    } else if (config->filter_mode == PID_TID_MODE) {
        if (filter->pid == context->pid && filter->tid == context->tid) {
            u32 *flag = bpf_map_lookup_elem(&thread_filter, &p->event->context.comm);
            if (filter->thread_name_whitelist == 1) {
                if (flag != NULL && *flag == 2) {
                    return 1;
                }
                return 0;
            }
            if (flag != NULL && *flag == 1) {
                return 0;
            }
            return 1;
        }
        return 0;
    } else {
        return 0;
    }

    // 有时候希望对一些额外的进程进行追踪或者屏蔽
    // 还需要提供 uid pid tid 的黑白名单列表以达成更加精细的追踪

    return 1;
}

#endif