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
#include <linux/sched/types.h>
#include <linux/signal_types.h>
#include <linux/syscall_user_dispatch.h>
#endif
#include <linux/sched/prio.h>
#include <linux/mm_types_task.h>
#include <linux/rbtree.h>
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
#define PF_EXITING          0x00000004  /* Getting shut down */
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

/*
 * Integer metrics need fixed point arithmetic, e.g., sched/fair
 * has a few: load, load_avg, util_avg, freq, and capacity.
 *
 * We define a basic fixed point arithmetic range, and then formalize
 * all these metrics based on that basic range.
 */
#define SCHED_FIXEDPOINT_SHIFT  10
#define SCHED_FIXEDPOINT_SCALE  (1L << SCHED_FIXEDPOINT_SHIFT)

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

struct load_weight {
    unsigned long   weight;
    u32             inv_weight;
};

struct wake_q_node {
    struct wake_q_node *next;
};

struct sched_avg {
} ____cacheline_aligned;

struct sched_entity {
    /* For load-balancing: */
    struct load_weight      load;
    struct rb_node          run_node;
    struct list_head        group_node;
    unsigned int            on_rq;

    u64             exec_start;
    u64             sum_exec_runtime;
    u64             vruntime;
    u64             prev_sum_exec_runtime;

    u64             nr_migrations;

    int             depth;

    struct sched_entity     *parent;
    /* rq on which this entity is (to be) queued: */
    struct cfs_rq           *cfs_rq;
    /* rq "owned" by this entity/group: */
    struct cfs_rq           *my_q;
    /* cached value of my_q->h_nr_running */
    unsigned long           runnable_weight;

    /*
     * Per entity load average tracking.
     *
     * Put into separate cache line so it does not
     * collide with read-mostly values above.
     */
    struct sched_avg        avg;
};

struct sched_dl_entity {
    struct rb_node          rb_node;

    /*
     * Original scheduling parameters. Copied here from sched_attr
     * during sched_setattr(), they will remain the same until
     * the next sched_setattr().
     */
    u64             dl_runtime; /* Maximum runtime for each instance    */
    u64             dl_deadline;    /* Relative deadline of each instance   */
    u64             dl_period;  /* Separation of two instances (period) */
    u64             dl_bw;      /* dl_runtime / dl_period       */
    u64             dl_density; /* dl_runtime / dl_deadline     */

    /*
     * Actual scheduling parameters. Initialized with the values above,
     * they are continuously updated during task execution. Note that
     * the remaining runtime could be < 0 in case we are in overrun.
     */
    s64             runtime;    /* Remaining runtime for this instance  */
    u64             deadline;   /* Absolute deadline for this instance  */
    unsigned int            flags;      /* Specifying the scheduler behaviour   */

    /*
     * Some bool flags:
     *
     * @dl_throttled tells if we exhausted the runtime. If so, the
     * task has to wait for a replenishment to be performed at the
     * next firing of dl_timer.
     *
     * @dl_yielded tells if task gave up the CPU before consuming
     * all its available runtime during the last job.
     *
     * @dl_non_contending tells if the task is inactive while still
     * contributing to the active utilization. In other words, it
     * indicates if the inactive timer has been armed and its handler
     * has not been executed yet. This flag is useful to avoid race
     * conditions between the inactive timer handler and the wakeup
     * code.
     *
     * @dl_overrun tells if the task asked to be informed about runtime
     * overruns.
     */
    unsigned int            dl_throttled      : 1;
    unsigned int            dl_yielded        : 1;
    unsigned int            dl_non_contending : 1;
    unsigned int            dl_overrun    : 1;

#if 0
    /*
     * Bandwidth enforcement timer. Each -deadline task has its
     * own bandwidth to be enforced, thus we need one timer per task.
     */
    struct hrtimer          dl_timer;

    /*
     * Inactive timer, responsible for decreasing the active utilization
     * at the "0-lag time". When a -deadline task blocks, it contributes
     * to GRUB's active utilization until the "0-lag time", hence a
     * timer is needed to decrease the active utilization at the correct
     * time.
     */
    struct hrtimer inactive_timer;
#endif

    /*
     * Priority Inheritance. When a DEADLINE scheduling entity is boosted
     * pi_se points to the donor, otherwise points to the dl_se it belongs
     * to (the original one/itself).
     */
    struct sched_dl_entity *pi_se;
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

    struct mm_struct    *mm;
    struct mm_struct    *active_mm;

    void *stack;
    refcount_t usage;

    int on_cpu;

    /* Per task flags (PF_*), defined further below: */
    unsigned int flags;

    int recent_used_cpu;

    int wake_cpu;

    int on_rq;

    unsigned int policy;


    int             prio;
    int             static_prio;
    int             normal_prio;
    unsigned int    rt_priority;

    /* A live task holds one reference: */
    refcount_t stack_refcount;

    /* Filesystem information: */
    struct fs_struct        *fs;

    /* Open file information: */
    struct files_struct     *files;

    /* Namespaces: */
    struct nsproxy *nsproxy;

    /* Signal handlers: */
    struct signal_struct *signal;

    struct wake_q_node wake_q;

    /* Protection of the PI data structures: */
    raw_spinlock_t pi_lock;

    /* VM state: */
    struct reclaim_state *reclaim_state;

    unsigned short migration_disabled;

    struct sched_entity     se;
    struct sched_dl_entity  dl;
    const struct sched_class *sched_class;

    int nr_cpus_allowed;
    const cpumask_t *cpus_ptr;
    cpumask_t *user_cpus_ptr;
    cpumask_t cpus_mask;

    union {
        refcount_t      rcu_users;
        struct rcu_head rcu;
    };

    /* Scheduler bits, serialized by scheduler locks: */
    unsigned            sched_reset_on_fork:1;
    unsigned            sched_contributes_to_load:1;
    unsigned            sched_migrated:1;

    /* Force alignment to the next boundary: */
    unsigned            :0;

    /* Unserialized, strictly 'current' */

    /*
     * This field must not be in the scheduler word above due to wakelist
     * queueing no longer being serialized by p->on_cpu. However:
     *
     * p->XXX = X;          ttwu()
     * schedule()             if (p->on_rq && ..) // false
     *   smp_mb__after_spinlock();    if (smp_load_acquire(&p->on_cpu) && //true
     *   deactivate_task()            ttwu_queue_wakelist())
     *     p->on_rq = 0;            p->sched_remote_wakeup = Y;
     *
     * guarantees all stores of 'current' are visible before
     * ->sched_remote_wakeup gets used, so it can be in this word.
     */
    unsigned            sched_remote_wakeup:1;

    /* Bit to tell LSMs we're in execve(): */
    unsigned            in_execve:1;
    unsigned            in_iowait:1;

    /* CLONE_CHILD_SETTID: */
    int __user          *set_child_tid;

    /* CLONE_CHILD_CLEARTID: */
    int __user          *clear_child_tid;

    /* PF_KTHREAD | PF_IO_WORKER */
    void                *worker_private;

    int pagefault_disabled;

    pid_t               pid;

    /* Process credentials: */

    /* Tracer's credentials at attach: */
    const struct cred __rcu     *ptracer_cred;

    /* Objective and real subjective task credentials (COW): */
    const struct cred __rcu     *real_cred;

    /* Effective (overridable) subjective task credentials (COW): */
    const struct cred __rcu     *cred;

    /*
     * executable name, excluding path.
     *
     * - normally initialized setup_new_exec()
     * - access it with [gs]et_task_comm()
     * - lock it with task_lock()
     */
    char comm[TASK_COMM_LEN];

    struct nameidata *nameidata;

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

    /* Stacked block device info: */
    struct bio_list         *bio_list;

    /* Stack plugging: */
    struct blk_plug         *plug;

    /* Protection against (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed, mempolicy: */
    spinlock_t alloc_lock;

    /*
     * Time slack values; these are used to round up poll() and
     * select() etc timeout values. These are in nanoseconds.
     */
    u64 timer_slack_ns;
    u64 default_timer_slack_ns;

    struct task_group *sched_task_group;

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

static __always_inline bool need_resched(void)
{
    return unlikely(tif_need_resched());
}

/* runqueue "owned" by this group */
static inline struct cfs_rq *group_cfs_rq(struct sched_entity *grp)
{
    return grp->my_q;
}

extern void io_schedule(void);

extern struct root_domain def_root_domain;
extern struct mutex sched_domains_mutex;

/* Increase resolution of cpu_capacity calculations */
# define SCHED_CAPACITY_SHIFT       SCHED_FIXEDPOINT_SHIFT
# define SCHED_CAPACITY_SCALE       (1L << SCHED_CAPACITY_SHIFT)

#endif /* _LINUX_SCHED_H */
