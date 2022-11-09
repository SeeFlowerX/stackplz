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

SEC("uprobe/stack")
int probe_stack(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u32 tid = current_pid_tgid & 0xffffffff;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid >> 32;

    if (0xaabbccaa != uid) {
        return 0;
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