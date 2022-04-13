/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <uapi/linux/sched.h>
#include <linux/refcount.h>
#include <asm/thread_info.h>

struct task_struct {
    /*
     * For reasons of header soup (see current_thread_info()), this
     * must be the first element of task_struct.
     */
    struct thread_info  thread_info;

    /* A live task holds one reference: */
    refcount_t          stack_refcount;
};

#endif /* _LINUX_SCHED_H */
