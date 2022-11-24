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

    // if (0xaabbccaa != uid) {
    //     return 0;
    // }

    // if (((tid >> 16) + pid) > 0xaabbcc11 && 0xaabbcc99 != pid) {
    //     return 0;
    // }

    if (filter->nr != ctx->id) {
        return 0;
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