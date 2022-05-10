/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <uapi/linux/sched.h>
#include <linux/refcount.h>
#include <asm/thread_info.h>

/* Used in tsk->state: */
#define TASK_RUNNING            0x0000
#define TASK_INTERRUPTIBLE      0x0001
#define TASK_UNINTERRUPTIBLE    0x0002
#define __TASK_STOPPED          0x0004
#define __TASK_TRACED           0x0008

#define MAX_SCHEDULE_TIMEOUT    LONG_MAX

/*
 * Per process flags
 */
#define PF_MEMALLOC_NOFS    0x00040000  /* All allocation requests will inherit GFP_NOFS */
#define PF_MEMALLOC_NOIO    0x00080000  /* All allocation requests will inherit GFP_NOIO */

#define PF_KTHREAD          0x00200000  /* I am a kernel thread */
#define PF_MEMALLOC_PIN     0x10000000  /* Allocation context constrained to zones which allow long term pinning. */


static inline int _cond_resched(void) { return 0; }

#define cond_resched() ({           \
    ___might_sleep(__FILE__, __LINE__, 0);  \
    _cond_resched();            \
})

#define __set_current_state(state_value) \
    current->state = (state_value)

struct task_struct {
    /*
     * For reasons of header soup (see current_thread_info()), this
     * must be the first element of task_struct.
     */
    struct thread_info  thread_info;

    /* -1 unrunnable, 0 runnable, >0 stopped: */
    volatile long   state;

    /* Per task flags (PF_*), defined further below: */
    unsigned int    flags;

    /* A live task holds one reference: */
    refcount_t          stack_refcount;
};

extern long schedule_timeout(long timeout);

extern int wake_up_process(struct task_struct *tsk);

#endif /* _LINUX_SCHED_H */
