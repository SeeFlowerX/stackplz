#include "utils.h"

#include "vmlinux_510.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

// #include "common/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} fake_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} brk_events SEC(".maps");

// https://arthurchiao.art/blog/bpf-ringbuf-zh/
// https://mozillazg.com/2022/05/ebpf-libbpfgo-use-ringbuf-map.html
// https://github.com/mozillazg/hello-libbpfgo
// 根据文章，以及 cilium/ebpf 中关于读取 ringbuf 的部分
// 可以知道 BPF_MAP_TYPE_RINGBUF 的 max_entries 就是环形缓冲区的大小
// 调整大小可以考虑加载前编辑常量实现
// 后续考虑迁移到 ringbuf 方式读取
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 32 * 1024 * 1024 /* 32 MB */);
// } fake_events SEC(".maps");

// SEC("perf_event")
// int perf_event_handler(void *ctx) {
//     struct bpf_perf_event_data *bpf_ctx = (struct bpf_perf_event_data *)(ctx);
//     struct pt_regs *regs = (struct pt_regs *)(&bpf_ctx->regs);

//     // u64 pc = READ_KERN(regs->pc);
//     // u64 sp = READ_KERN(regs->sp);
//     u64 pc = 0;
//     u64 sp = 0;

//     bpf_probe_read_user(&pc, sizeof(pc), &regs->pc);
//     bpf_probe_read_user(&sp, sizeof(sp), &regs->sp);
//     int pid = bpf_get_current_pid_tgid() >> 32;
//     // // save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 2);
//     // // save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 3);

//     // bpf_printk("[perf_event] pc:0x%lx sp:0x%lx\n", pc, sp);
//     bpf_printk("[perf_event] called pid:%d\n", pid);
//     // bpf_printk("[perf_event] called pc:0x%lx\n", &regs->pc);
//     return 0;
// }