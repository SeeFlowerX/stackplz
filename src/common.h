#ifndef STACKPLZ_COMMON_H
#define STACKPLZ_COMMON_H

#include "vmlinux_510.h"

#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

#include "maps.h"

static void get_file_path(struct file *file, char *buf, size_t size)
{
	struct qstr dname;

	dname = BPF_CORE_READ(file, f_path.dentry, d_name);
	bpf_probe_read_kernel(buf, size, dname.name);
}

// #define __uint(name, val) int (*name)[val]
// #define __type(name, val) typeof(val) *name
// #define __array(name, val) typeof(val) *name[]

struct sys_enter_args
{
    unsigned long long ignore;
    long id;
    unsigned long args[6];
};

// struct pt_regs {
//     union {
//         struct user_pt_regs user_regs;
//         struct {
//             u64 regs[31];
//             u64 sp;
//             u64 pc;
//             u64 pstate;
//         };
//     };
//     u64 orig_x0;
//     s32 syscallno;
//     u32 unused2;
//     u64 orig_addr_limit;
//     u64 pmr_save;
//     u64 stackframe[2];
//     u64 lockdep_hardirqs;
//     u64 exit_rcu;
// };

// https://github.com/aquasecurity/tracee/blob/main/pkg/ebpf/c/common/common.h

#define GET_FIELD_ADDR(field) &field

#define READ_KERN(ptr)                                                                         \
    ({                                                                                         \
        typeof(ptr) _val;                                                                      \
        __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
        bpf_probe_read((void *) &_val, sizeof(_val), &ptr);                                    \
        _val;                                                                                  \
    })

#define READ_KERN_STR_INTO(dst, src) bpf_probe_read_str((void *) &dst, sizeof(dst), src)

#define READ_USER(ptr)                                                                         \
    ({                                                                                         \
        typeof(ptr) _val;                                                                      \
        __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
        bpf_probe_read_user((void *) &_val, sizeof(_val), &ptr);                               \
        _val;                                                                                  \
    })

#define BPF_READ(src, a, ...)                                                                  \
    ({                                                                                         \
        ___type((src), a, ##__VA_ARGS__) __r;                                                  \
        BPF_PROBE_READ_INTO(&__r, (src), a, ##__VA_ARGS__);                                    \
        __r;                                                                                   \
    })

char __license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

#endif
