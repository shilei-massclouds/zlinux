/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

/*
 * Define 'struct task_struct' and provide the main scheduler
 * APIs (schedule(), wakeup variants, etc.)
 */

#include <uapi/linux/sched.h>

#include <asm/current.h>

#include <linux/pid.h>
#if 0
#include <linux/sem.h>
#include <linux/shm.h>
#endif
#include <linux/mutex.h>
#if 0
#include <linux/plist.h>
#include <linux/hrtimer.h>
#include <linux/irqflags.h>
#include <linux/seccomp.h>
#endif
#include <linux/nodemask.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#if 0
#include <linux/resource.h>
#include <linux/latencytop.h>
#include <linux/sched/prio.h>
#include <linux/sched/types.h>
#include <linux/signal_types.h>
#include <linux/syscall_user_dispatch.h>
#endif
#include <linux/mm_types_task.h>
#if 0
#include <linux/task_io_accounting.h>
#include <linux/posix-timers.h>
#include <linux/rseq.h>
#include <linux/seqlock.h>
#include <asm/kmap_size.h>
#endif

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

    void *stack;
    refcount_t usage;

    /* Per task flags (PF_*), defined further below: */
    unsigned int flags;

    /* A live task holds one reference: */
    refcount_t stack_refcount;

    /* Signal handlers: */
    struct signal_struct *signal;

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

    struct vm_struct *stack_vm_area;

    /* CPU-specific state of this task: */
    struct thread_struct        thread;
};

extern unsigned long init_stack[THREAD_SIZE / sizeof(unsigned long)];

extern long schedule_timeout(long timeout);

extern int wake_up_process(struct task_struct *tsk);

extern void schedule_preempt_disabled(void);

#endif /* _LINUX_SCHED_H */
