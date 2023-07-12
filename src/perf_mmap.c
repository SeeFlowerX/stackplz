#include "utils.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} fake_events SEC(".maps");


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