#include "common.h"

struct hook_data_event_t {
    u32 pid;
    u32 tid;
    u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} stack_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct hook_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

// 用于设置过滤配置
struct filter_t {
    u32 uid;
    u32 pid;
    u32 tid_blacklist_mask;
    u32 tid_blacklist[MAX_TID_BLACKLIST_COUNT];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct filter_t);
    __uint(max_entries, 1);
} filter_map SEC(".maps");

SEC("uprobe/stack")
int probe_stack(struct pt_regs* ctx) {
    u32 filter_key = 0;
    struct filter_t* filter = bpf_map_lookup_elem(&filter_map, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid >> 32;
    if (filter->uid != 0 && filter->uid != uid) {
        return 0;
    }

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u32 tid = current_pid_tgid & 0xffffffff;
    if (filter->pid != 0 && filter->pid != pid) {
        return 0;
    }

    #ifdef DEBUG_PRINT
    char fmt0[] = "debug0, tid:%d mask:%d\n";
    bpf_trace_printk(fmt0, sizeof(fmt0), tid, filter->tid_blacklist_mask);
    #endif

    #pragma unroll
    for (int i = 0; i < MAX_TID_BLACKLIST_COUNT; i++) {
        if ((filter->tid_blacklist_mask & (1 << i))) {

            #ifdef DEBUG_PRINT
            char fmt1[] = "debug1, tid:%d filter_tid:%d\n";
            bpf_trace_printk(fmt1, sizeof(fmt1), tid, filter->tid_blacklist[i]);
            #endif

            if (filter->tid_blacklist[i] == tid) {
                // 在tid黑名单直接跳过
                return 0;
            }
        } else {
            // 避免不必要的循环
            break;
        }
    }

    u32 zero = 0;
    struct hook_data_event_t* event = bpf_map_lookup_elem(&data_buffer_heap, &zero);
    if (event == NULL) {
        return 0;
    }

    event->pid = pid;
    event->tid = tid;
    event->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    long status = bpf_perf_event_output(ctx, &stack_events, BPF_F_CURRENT_CPU, event, sizeof(struct hook_data_event_t));

    return 0;
}