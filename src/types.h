#ifndef __STACKPLZ_TYPES_H__
#define __STACKPLZ_TYPES_H__

#include "common/consts.h"

typedef struct common_filter {
    u32 uid;
    u32 pid;
    u32 tid;
    u32 blacklist_pids;
    u32 blacklist_tids;
    u32 blacklist_comms;
    u32 is_32bit;
} common_filter_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct config_entry {
    u32 filter_mode;
    u32 stackplz_pid;
} config_entry_t;

enum filter_mode_e
{
    UNKNOWN_MODE,
    UID_MODE,
    PID_MODE,
    PID_TID_MODE
};

enum event_id_e
{
    SYSCALL_ENTER = 456,
    SYSCALL_EXIT
};

enum arg_type_e
{
	TYPE_NONE = 0,
	TYPE_NUM,
	TYPE_INT,
	TYPE_UINT,
	TYPE_UINT32,
	TYPE_UINT64,
	TYPE_STRING,
	TYPE_STRING_ARR,
	TYPE_POINTER,
	TYPE_STRUCT,
	TYPE_TIMESPEC,
	TYPE_STAT,
	TYPE_STATFS,
	TYPE_SIGACTION,
	TYPE_UTSNAME,
	TYPE_SOCKADDR,
	TYPE_RUSAGE,
	TYPE_IOVEC,
	TYPE_SIGSET,
	TYPE_POLLFD,
	TYPE_ARGASSIZE,
};

enum read_type_e
{
	FORBIDDEN = 0,
	SYS_ENTER,
	SYS_EXIT
};

typedef struct event_context {
    u64 ts;
    u32 eventid;
    u32 host_tid;
    u32 host_pid;
    u32 tid;
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u8 argnum;
    char padding[7];
} event_context_t;

typedef struct event_data {
    event_context_t context;
    char args[ARGS_BUF_SIZE];
    u32 buf_off;
    struct task_struct *task;
} event_data_t;

#define MAX_EVENT_SIZE sizeof(event_context_t) + ARGS_BUF_SIZE

typedef struct program_data {
    config_entry_t *config;
    event_data_t *event;
    void *ctx;
} program_data_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;


typedef struct vma_arg {
    u64 vma_ptr;
} vma_arg_t;

#define MAX_CACHED_PATH_SIZE 64

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

typedef struct file_info {
    union {
        char pathname[MAX_CACHED_PATH_SIZE];
        char *pathname_p;
    };
    dev_t device;
    unsigned long inode;
    u64 ctime;
} file_info_t;

#endif