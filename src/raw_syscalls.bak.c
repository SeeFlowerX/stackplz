#include "common.h"

struct syscall_data_event_t {
    u32 pid;
    u32 tid;
    u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
    long NR;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} syscall_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct syscall_data_event_t);
    __uint(max_entries, 1);
} sys_buffer_heap SEC(".maps");

// 用于设置过滤配置
struct filter_t {
    u32 uid;
    u32 pid;
    u32 nr;
    u32 tid_blacklist_mask;
    u32 tid_blacklist[MAX_COUNT];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct filter_t);
    __uint(max_entries, 1);
} filter_map SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int raw_syscalls_sys_enter(struct sys_enter_args* ctx) {
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

    if (filter->nr != ctx->id) {
        return 0;
    }

    #pragma unroll
    for (int i = 0; i < MAX_COUNT; i++) {
        if ((filter->tid_blacklist_mask & (1 << i))) {
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
    struct syscall_data_event_t* event = bpf_map_lookup_elem(&sys_buffer_heap, &zero);
    if (event == NULL) {
        return 0;
    }

    event->pid = pid;
    event->tid = tid;
    event->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->NR = ctx->id;

    long status = bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, event, sizeof(struct syscall_data_event_t));

    return 0;
}