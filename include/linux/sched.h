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

#define TASK_WAKEKILL           0x0100

#define TASK_KILLABLE           (TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)

#define MAX_SCHEDULE_TIMEOUT    LONG_MAX

/*
 * Per process flags
 */
#define PF_MEMALLOC_NOFS    0x00040000  /* All allocation requests will inherit GFP_NOFS */
#define PF_MEMALLOC_NOIO    0x00080000  /* All allocation requests will inherit GFP_NOIO */

#define PF_KTHREAD          0x00200000  /* I am a kernel thread */
#define PF_MEMALLOC_PIN     0x10000000  /* Allocation context constrained to zones which allow long term pinning. */

/* Task command name length: */
#define TASK_COMM_LEN   16

static inline int _cond_resched(void) { return 0; }

#define cond_resched() ({           \
    ___might_sleep(__FILE__, __LINE__, 0);  \
    _cond_resched();            \
})

#define __set_current_state(state_value)                \
    do {                                \
        WRITE_ONCE(current->__state, (state_value));        \
    } while (0)

#define set_current_state(state_value)                  \
    do {                                \
        smp_store_mb(current->__state, (state_value));      \
    } while (0)

struct wake_q_node {
    struct wake_q_node *next;
};

struct task_struct {
    /*
     * For reasons of header soup (see current_thread_info()), this
     * must be the first element of task_struct.
     */
    struct thread_info thread_info;

    unsigned int __state;

    refcount_t usage;

    /* Per task flags (PF_*), defined further below: */
    unsigned int flags;

    /* A live task holds one reference: */
    refcount_t stack_refcount;

    struct wake_q_node wake_q;

    /* VM state: */
    struct reclaim_state *reclaim_state;

    /*
     * executable name, excluding path.
     *
     * - normally initialized setup_new_exec()
     * - access it with [gs]et_task_comm()
     * - lock it with task_lock()
     */
    char comm[TASK_COMM_LEN];
};

extern long schedule_timeout(long timeout);

extern int wake_up_process(struct task_struct *tsk);

extern void schedule_preempt_disabled(void);

#endif /* _LINUX_SCHED_H */
