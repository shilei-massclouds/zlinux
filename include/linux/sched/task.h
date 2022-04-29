/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_TASK_H
#define _LINUX_SCHED_TASK_H

#include <linux/sched.h>
#include <linux/uaccess.h>

extern struct task_struct init_task;

extern pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags);

struct kernel_clone_args {
    u64 flags;
    int exit_signal;
    unsigned long stack;
    unsigned long stack_size;
    int __user *pidfd;
    int __user *child_tid;
    int __user *parent_tid;
#if 0
    unsigned long tls;
    pid_t *set_tid;
    /* Number of elements in *set_tid */
    size_t set_tid_size;
    int cgroup;
    struct cgroup *cgrp;
    struct css_set *cset;
#endif
};

#endif /* _LINUX_SCHED_TASK_H */
