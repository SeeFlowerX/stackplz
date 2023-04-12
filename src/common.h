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

size_t strlen(const char *s)
{
	// 写法一
	// int len;
    // for (len = 0; len < PATH_MAX; len++) {
    //     if (*sc == '\0') {
    //         break;
    //     }
    //     sc++;
    // }
    // return len;

	// 写法二 感觉好看一点
    const char *sc = s;
    for (int i = 0; i < PATH_MAX; i++) {
        if (*sc == '\0') {
            break;
        }
        sc++;
    }

	// 写法三
	// int offset = 0;
    // for (sc = s; *sc != '\0' && offset < PATH_MAX; ++sc)
    // {
    //     offset += 1;
    // };

	return sc - s;
}

struct sys_enter_args
{
    unsigned long long ignore;
    long id;
    unsigned long args[6];
};

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
