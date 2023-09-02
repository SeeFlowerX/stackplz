#ifndef __STACKPLZ_CONSTS_H__
#define __STACKPLZ_CONSTS_H__

#define TASK_COMM_LEN 16
#define MAX_COUNT 20
#define MAX_FILTER_COUNT 6
#define MAX_PATH_COMPONENTS   48

// clang-format off
#define MAX_PERCPU_BUFSIZE (1 << 15)  // set by the kernel as an upper bound
#define PATH_MAX    4096
#define MAX_STRING_SIZE    4096       // same as PATH_MAX
#define MAX_BYTES_ARR_SIZE    4096       // same as PATH_MAX
#define MAX_BUF_READ_SIZE    4096
#define ARGS_BUF_SIZE       32000

// 配合 common_list 使用的 它们的间隔范围都是 0x400
// 意味着它们每个选项有 1024 大小的范围 用于过滤完全足够了
// 不过要注意 common_list 的总大小上限设置的是 1024
#define SYS_WHITELIST_START 0x400
#define SYS_BLACKLIST_START SYS_WHITELIST_START + 0x400
#define UID_WHITELIST_START SYS_BLACKLIST_START + 0x400
#define UID_BLACKLIST_START UID_WHITELIST_START + 0x400
#define PID_WHITELIST_START UID_BLACKLIST_START + 0x400
#define PID_BLACKLIST_START PID_WHITELIST_START + 0x400
#define TID_WHITELIST_START PID_BLACKLIST_START + 0x400
#define TID_BLACKLIST_START TID_WHITELIST_START + 0x400

#define THREAD_NAME_WHITELIST 1
#define THREAD_NAME_BLACKLIST 2

#define TRACE_COMMON 0
#define TRACE_ALL 1

enum buf_idx_e
{
    STRING_BUF_IDX,
    ZERO_BUF_IDX,
    MAX_BUFFERS
};


#endif // __STACKPLZ_CONSTS_H__