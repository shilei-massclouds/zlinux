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

#define TASK_NEW                0x0800

#define TASK_KILLABLE           (TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)

#define MAX_SCHEDULE_TIMEOUT    LONG_MAX

/*
 * Per process flags
 */
#define PF_IDLE             0x00000002  /* I am an IDLE thread */
#define PF_IO_WORKER        0x00000010  /* Task is an IO worker */
#define PF_WQ_WORKER        0x00000020  /* I'm a workqueue worker */
#define PF_FORKNOEXEC       0x00000040  /* Forked but didn't exec */
#define PF_SUPERPRIV        0x00000100  /* Used super-user privileges */
#define PF_NPROC_EXCEEDED   0x00001000  /* set_user() noticed that RLIMIT_NPROC was exceeded */
#define PF_MEMALLOC_NOFS    0x00040000  /* All allocation requests will inherit GFP_NOFS */
#define PF_MEMALLOC_NOIO    0x00080000  /* All allocation requests will inherit GFP_NOIO */

#define PF_KTHREAD          0x00200000  /* I am a kernel thread */
#define PF_NO_SETAFFINITY   0x04000000  /* Userland is not allowed to meddle with cpus_mask */
#define PF_MEMALLOC_PIN     0x10000000  /* Allocation context constrained to zones which allow long term pinning. */

/* Wake flags. The first three directly map to some SD flag value */
#define WF_EXEC     0x02 /* Wakeup after exec; maps to SD_BALANCE_EXEC */
#define WF_FORK     0x04 /* Wakeup after fork; maps to SD_BALANCE_FORK */
#define WF_TTWU     0x08 /* Wakeup;            maps to SD_BALANCE_WAKE */

#define WF_SYNC     0x10 /* Waker goes to sleep after wakeup */
#define WF_MIGRATED 0x20 /* Internal use, task got migrated */
#define WF_ON_CPU   0x40 /* Wakee is on_cpu */

/* Task command name length: */
#define TASK_COMM_LEN   16

static inline int _cond_resched(void) { return 0; }

#define task_thread_info(task) (&(task)->thread_info)

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

    /* PID/PID hash table linkage. */
    struct pid *thread_pid;

    unsigned int __state;

    void *stack;
    refcount_t usage;

    /* Per task flags (PF_*), defined further below: */
    unsigned int flags;

    int recent_used_cpu;

    /* A live task holds one reference: */
    refcount_t stack_refcount;

    /* Namespaces: */
    struct nsproxy *nsproxy;

    /* Signal handlers: */
    struct signal_struct *signal;

    struct wake_q_node wake_q;

    /* Protection of the PI data structures: */
    raw_spinlock_t pi_lock;

    /* VM state: */
    struct reclaim_state *reclaim_state;

    const cpumask_t *cpus_ptr;
    cpumask_t       *user_cpus_ptr;
    cpumask_t       cpus_mask;

    union {
        refcount_t      rcu_users;
        struct rcu_head rcu;
    };

    /* CLONE_CHILD_SETTID: */
    int __user          *set_child_tid;

    /* CLONE_CHILD_CLEARTID: */
    int __user          *clear_child_tid;

    /* PF_KTHREAD | PF_IO_WORKER */
    void                *worker_private;

    int pagefault_disabled;

    pid_t               pid;

    /*
     * executable name, excluding path.
     *
     * - normally initialized setup_new_exec()
     * - access it with [gs]et_task_comm()
     * - lock it with task_lock()
     */
    char comm[TASK_COMM_LEN];

    struct vm_struct *stack_vm_area;

    struct completion *vfork_done;

    /*
     * Pointers to the (original) parent process, youngest child, younger sibling,
     * older sibling, respectively.  (p->father can be replaced with
     * p->real_parent->pid)
     */

    /* Real parent process: */
    struct task_struct __rcu    *real_parent;

    /* Recipient of SIGCHLD, wait4() reports: */
    struct task_struct __rcu    *parent;

    /*
     * Children/sibling form the list of natural children:
     */
    struct list_head        children;
    struct list_head        sibling;

    /* Protection against (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed, mempolicy: */
    spinlock_t alloc_lock;

    /*
     * Time slack values; these are used to round up poll() and
     * select() etc timeout values. These are in nanoseconds.
     */
    u64 timer_slack_ns;
    u64 default_timer_slack_ns;

    /* CPU-specific state of this task: */
    struct thread_struct    thread;
};

extern unsigned long init_stack[THREAD_SIZE / sizeof(unsigned long)];

extern long schedule_timeout(long timeout);

extern int wake_up_process(struct task_struct *tsk);

extern void schedule_preempt_disabled(void);

extern long schedule_timeout_uninterruptible(long timeout);

static inline void clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
    clear_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void clear_tsk_need_resched(struct task_struct *tsk)
{
    clear_tsk_thread_flag(tsk, TIF_NEED_RESCHED);
}

static inline struct pid *task_pid(struct task_struct *task)
{
    return task->thread_pid;
}

extern int
dup_user_cpus_ptr(struct task_struct *dst, struct task_struct *src, int node);

extern void wake_up_new_task(struct task_struct *tsk);

static inline unsigned int task_cpu(const struct task_struct *p)
{
    return READ_ONCE(task_thread_info(p)->cpu);
}

#endif /* _LINUX_SCHED_H */
