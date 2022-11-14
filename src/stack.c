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
    // 为什么要这么写 因为全局常量是5.3还是哪个版本才可以 只好用这个笨办法了
    // 我们知道 ((tid >> 16) + pid) 肯定是刚好等于 pid 本身的
    // 那么过滤 pid 的时候改成 0 
    // 则 pid 必 大于 0
    // 那么修改后面的数字为真正要过滤的 pid 值 如此可以实现过滤
    if (((tid >> 16) + pid) > 0xaabbcc11 && 0xaabbcc99 != pid) {
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