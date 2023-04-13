#ifndef __STACKPLZ_CONSTS_H__
#define __STACKPLZ_CONSTS_H__

#define TASK_COMM_LEN 16
#define MAX_COUNT 20
#define MAX_PATH_COMPONENTS   48

// clang-format off
#define MAX_PERCPU_BUFSIZE (1 << 15)  // set by the kernel as an upper bound
#define PATH_MAX    4096
#define MAX_STRING_SIZE    4096       // same as PATH_MAX
#define ARGS_BUF_SIZE       32000

enum buf_idx_e
{
    STRING_BUF_IDX,
    FILE_BUF_IDX,
    MAX_BUFFERS
};


#endif // __STACKPLZ_CONSTS_H__