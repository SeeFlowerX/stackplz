#ifndef __STACKPLZ_COMMON_H__
#define __STACKPLZ_COMMON_H__

#include "bpf_helpers.h"
#include "maps.h"

#include <vmlinux_510.h>

// helper macros for branch prediction
#ifndef likely
    #define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
    #define unlikely(x) __builtin_expect((x), 0)
#endif


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

#endif