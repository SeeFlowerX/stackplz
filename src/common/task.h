#ifndef __STACKPLZ_TASK_H__
#define __STACKPLZ_TASK_H__

#include "vmlinux_510.h"

#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "common/common.h"

static __always_inline u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;
    pid = READ_KERN(task->pids[PIDTYPE_PID].pid);
    level = READ_KERN(pid->level);
    return READ_KERN(pid->numbers[level].nr);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = READ_KERN(task->group_leader);
    return get_task_pid_vnr(group_leader);
}

#endif
