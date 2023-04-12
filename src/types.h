#ifndef __TRACEE_TYPES_H__
#define __TRACEE_TYPES_H__

#include "consts.h"

enum event_id_e
{
    SECURITY_FILE_MPROTECT = 456,
    SU_FILE_ACCESS
};

typedef struct event_context {
    u32 eventid;
    u32 pid;
    u32 tid;
    u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
    u8 argnum;
} event_context_t;

typedef struct event_data {
    event_context_t context;
    char args[ARGS_BUF_SIZE];
    u32 buf_off;
} event_data_t;

#define MAX_EVENT_SIZE sizeof(event_context_t) + ARGS_BUF_SIZE

typedef struct program_data {
    event_data_t *event;
    void *ctx;
} program_data_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;


typedef struct vma_arg {
    u64 vma_ptr;
} vma_arg_t;

#endif