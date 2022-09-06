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
#endif
#include <linux/shm.h>
#include <linux/mutex.h>
#include <linux/hrtimer.h>
#include <linux/plist.h>
#if 0
#include <linux/irqflags.h>
#include <linux/seccomp.h>
#endif
#include <linux/nodemask.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/resource.h>
#if 0
#include <linux/latencytop.h>
#include <linux/sched/types.h>
#include <linux/syscall_user_dispatch.h>
#endif
#include <linux/signal_types.h>
#include <linux/sched/prio.h>
#include <linux/mm_types_task.h>
#include <linux/rbtree.h>
#include <linux/posix-timers.h>
#include <linux/rseq.h>
#if 0
#include <linux/task_io_accounting.h>
#include <linux/seqlock.h>
#include <asm/kmap_size.h>
#endif

/* task_struct member predeclarations (sorted alphabetically): */
struct audit_context;
struct backing_dev_info;
struct bio_list;
struct blk_plug;
struct bpf_local_storage;
struct bpf_run_ctx;
struct capture_control;
struct cfs_rq;
struct fs_struct;
struct futex_pi_state;
struct io_context;
struct io_uring_task;
struct mempolicy;
struct nameidata;
struct nsproxy;
struct perf_event_context;
struct pid_namespace;
struct pipe_inode_info;
struct rcu_node;
struct reclaim_state;
struct robust_list_head;
struct root_domain;
struct rq;
struct sched_attr;
struct sched_param;
struct seq_file;
struct sighand_struct;
struct signal_struct;
struct task_delay_info;
struct task_group;

/* Increase resolution of cpu_capacity calculations */
# define SCHED_CAPACITY_SHIFT       SCHED_FIXEDPOINT_SHIFT
# define SCHED_CAPACITY_SCALE       (1L << SCHED_CAPACITY_SHIFT)

/* Used in tsk->state: */
#define TASK_RUNNING            0x0000
#define TASK_INTERRUPTIBLE      0x0001
#define TASK_UNINTERRUPTIBLE    0x0002
#define __TASK_STOPPED          0x0004
#define __TASK_TRACED           0x0008

/* Used in tsk->state again: */
#define TASK_PARKED             0x0040
#define TASK_DEAD               0x0080
#define TASK_WAKEKILL           0x0100
#define TASK_WAKING             0x0200
#define TASK_NOLOAD             0x0400
#define TASK_NEW                0x0800

#define TASK_KILLABLE           (TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)

/* Convenience macros for the sake of wake_up(): */
#define TASK_NORMAL             (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)

#define MAX_SCHEDULE_TIMEOUT    LONG_MAX

#define task_is_running(task) \
    (READ_ONCE((task)->__state) == TASK_RUNNING)

#define task_is_traced(task) \
    ((READ_ONCE(task->__state) & __TASK_TRACED) != 0)

#define task_is_stopped(task) \
    ((READ_ONCE(task->__state) & __TASK_STOPPED) != 0)

#define task_is_stopped_or_traced(task) \
    ((READ_ONCE(task->__state) & (__TASK_STOPPED | __TASK_TRACED)) != 0)

/*
 * Per process flags
 */
#define PF_IDLE             0x00000002  /* I am an IDLE thread */
#define PF_EXITING          0x00000004  /* Getting shut down */
#define PF_IO_WORKER        0x00000010  /* Task is an IO worker */
#define PF_WQ_WORKER        0x00000020  /* I'm a workqueue worker */
#define PF_FORKNOEXEC       0x00000040  /* Forked but didn't exec */
#define PF_SUPERPRIV        0x00000100  /* Used super-user privileges */
#define PF_MEMALLOC         0x00000800  /* Allocating memory */
#define PF_NPROC_EXCEEDED   0x00001000  /* set_user() noticed that RLIMIT_NPROC was exceeded */
#define PF_NOFREEZE         0x00008000  /* This thread should not be frozen */
#define PF_FROZEN           0x00010000  /* Frozen for system suspend */
#define PF_KSWAPD           0x00020000  /* I am kswapd */
#define PF_MEMALLOC_NOFS    0x00040000  /* All allocation requests will inherit GFP_NOFS */
#define PF_MEMALLOC_NOIO    0x00080000  /* All allocation requests will inherit GFP_NOIO */

#define PF_LOCAL_THROTTLE   0x00100000  /* Throttle writes only against the bdi
                                           I write to, I am cleaning dirty
                                           pages from some other bdi. */

#define PF_KTHREAD          0x00200000  /* I am a kernel thread */
#define PF_RANDOMIZE        0x00400000  /* Randomize virtual address space */
#define PF_NO_SETAFFINITY   0x04000000  /* Userland is not allowed to meddle with cpus_mask */
#define PF_MCE_EARLY        0x08000000      /* Early kill for mce process policy */
#define PF_MEMALLOC_PIN     0x10000000  /* Allocation context constrained to zones which allow long term pinning. */
#define PF_FREEZER_SKIP     0x40000000  /* Freezer should not count it as freezable */
#define PF_SUSPEND_TASK     0x80000000      /* This thread called freeze_processes() and should not be frozen */

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

/*
 * Utilization clamp constraints.
 * @UCLAMP_MIN: Minimum utilization
 * @UCLAMP_MAX: Maximum utilization
 * @UCLAMP_CNT: Utilization clamp constraints count
 */
enum uclamp_id {
    UCLAMP_MIN = 0,
    UCLAMP_MAX,
    UCLAMP_CNT
};

struct load_weight {
    unsigned long   weight;
    u32             inv_weight;
};

struct wake_q_node {
    struct wake_q_node *next;
};

/*
 * Map the event mask on the user-space ABI enum rseq_cs_flags
 * for direct mask checks.
 */
enum rseq_event_mask_bits {
    RSEQ_EVENT_PREEMPT_BIT  = RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT,
    RSEQ_EVENT_SIGNAL_BIT   = RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT,
    RSEQ_EVENT_MIGRATE_BIT  = RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT,
};

/**
 * struct util_est - Estimation utilization of FAIR tasks
 * @enqueued: instantaneous estimated utilization of a task/cpu
 * @ewma:     the Exponential Weighted Moving Average (EWMA)
 *            utilization of a task
 *
 * Support data structure to track an Exponential Weighted Moving Average
 * (EWMA) of a FAIR task's utilization. New samples are added to the moving
 * average each time a task completes an activation. Sample's weight is chosen
 * so that the EWMA will be relatively insensitive to transient changes to the
 * task's workload.
 *
 * The enqueued attribute has a slightly different meaning for tasks and cpus:
 * - task:   the task's util_avg at last task dequeue time
 * - cfs_rq: the sum of util_est.enqueued for each RUNNABLE task on that CPU
 * Thus, the util_est.enqueued of a task represents the contribution on the
 * estimated utilization of the CPU where that task is currently enqueued.
 *
 * Only for tasks we track a moving average of the past instantaneous
 * estimated utilization. This allows to absorb sporadic drops in utilization
 * of an otherwise almost periodic task.
 *
 * The UTIL_AVG_UNCHANGED flag is used to synchronize util_est with util_avg
 * updates. When a task is dequeued, its util_est should not be updated if its
 * util_avg has not been updated in the meantime.
 * This information is mapped into the MSB bit of util_est.enqueued at dequeue
 * time. Since max value of util_est.enqueued for a task is 1024 (PELT util_avg
 * for a task) it is safe to use MSB.
 */
struct util_est {
    unsigned int            enqueued;
    unsigned int            ewma;
#define UTIL_EST_WEIGHT_SHIFT       2
#define UTIL_AVG_UNCHANGED      0x80000000
} __attribute__((__aligned__(sizeof(u64))));

/*
 * The load/runnable/util_avg accumulates an infinite geometric series
 * (see __update_load_avg_cfs_rq() in kernel/sched/pelt.c).
 *
 * [load_avg definition]
 *
 *   load_avg = runnable% * scale_load_down(load)
 *
 * [runnable_avg definition]
 *
 *   runnable_avg = runnable% * SCHED_CAPACITY_SCALE
 *
 * [util_avg definition]
 *
 *   util_avg = running% * SCHED_CAPACITY_SCALE
 *
 * where runnable% is the time ratio that a sched_entity is runnable and
 * running% the time ratio that a sched_entity is running.
 *
 * For cfs_rq, they are the aggregated values of all runnable and blocked
 * sched_entities.
 *
 * The load/runnable/util_avg doesn't directly factor frequency scaling and CPU
 * capacity scaling. The scaling is done through the rq_clock_pelt that is used
 * for computing those signals (see update_rq_clock_pelt())
 *
 * N.B., the above ratios (runnable% and running%) themselves are in the
 * range of [0, 1]. To do fixed point arithmetics, we therefore scale them
 * to as large a range as necessary. This is for example reflected by
 * util_avg's SCHED_CAPACITY_SCALE.
 *
 * [Overflow issue]
 *
 * The 64-bit load_sum can have 4353082796 (=2^64/47742/88761) entities
 * with the highest load (=88761), always runnable on a single cfs_rq,
 * and should not overflow as the number already hits PID_MAX_LIMIT.
 *
 * For all other cases (including 32-bit kernels), struct load_weight's
 * weight will overflow first before we do, because:
 *
 *    Max(load_avg) <= Max(load.weight)
 *
 * Then it is the load_weight's responsibility to consider overflow
 * issues.
 */
struct sched_avg {
    u64             last_update_time;
    u64             load_sum;
    u64             runnable_sum;
    u32             util_sum;
    u32             period_contrib;
    unsigned long           load_avg;
    unsigned long           runnable_avg;
    unsigned long           util_avg;
    struct util_est         util_est;
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

struct sched_rt_entity {
    struct list_head        run_list;
    unsigned long           timeout;
    unsigned long           watchdog_stamp;
    unsigned int            time_slice;
    unsigned short          on_rq;
    unsigned short          on_list;

    struct sched_rt_entity      *back;
} __randomize_layout;

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

    /*
     * Priority Inheritance. When a DEADLINE scheduling entity is boosted
     * pi_se points to the donor, otherwise points to the dl_se it belongs
     * to (the original one/itself).
     */
    struct sched_dl_entity *pi_se;
};

/**
 * struct prev_cputime - snapshot of system and user cputime
 * @utime: time spent in user mode
 * @stime: time spent in system mode
 * @lock: protects the above two fields
 *
 * Stores previous user/system time values such that we can guarantee
 * monotonicity.
 */
struct prev_cputime {
    u64             utime;
    u64             stime;
    raw_spinlock_t  lock;
};

struct sched_info {
};

struct task_struct {
    /*
     * For reasons of header soup (see current_thread_info()), this
     * must be the first element of task_struct.
     */
    struct thread_info thread_info;

    /* PID/PID hash table linkage. */
    struct pid *thread_pid;
    struct hlist_node pid_links[PIDTYPE_MAX];
    struct list_head thread_group;

    struct list_head    thread_node;

    unsigned int __state;

    struct sched_info   sched_info;

    struct list_head    tasks;

    struct plist_node       pushable_tasks;
    struct rb_node          pushable_dl_tasks;

    struct mm_struct    *mm;
    struct mm_struct    *active_mm;

    /* Per-thread vma caching: */
    struct vmacache     vmacache;

    int exit_state;
    int exit_code;
    int exit_signal;
    /* The signal sent when the parent dies: */
    int pdeath_signal;

    /* Used for emulating ABI behavior of previous Linux versions: */
    unsigned int personality;

    /* Thread group tracking: */
    u64 parent_exec_id;
    u64 self_exec_id;

    void *stack;
    refcount_t usage;

    int on_cpu;
    struct __call_single_node   wake_entry;
    unsigned int            wakee_flips;
    unsigned long           wakee_flip_decay_ts;
    struct task_struct      *last_wakee;

    /*
     * recent_used_cpu is initially set as the last CPU used by a task
     * that wakes affine another task. Waker/wakee relationships can
     * push tasks around a CPU where each wakeup moves to the next one.
     * Tracking a recently used CPU allows a quick search for a recently
     * used CPU that may be idle.
     */
    int             recent_used_cpu;
    int             wake_cpu;

    /* Per task flags (PF_*), defined further below: */
    unsigned int flags;

    int on_rq;

    /* List of struct preempt_notifier: */
    struct hlist_head preempt_notifiers;

    unsigned int policy;

    int             prio;
    int             static_prio;
    int             normal_prio;
    unsigned int    rt_priority;

    /* A live task holds one reference: */
    refcount_t stack_refcount;

    //struct sysv_sem         sysvsem;
    struct sysv_shm         sysvshm;

    unsigned long           last_switch_count;
    unsigned long           last_switch_time;

    /* Filesystem information: */
    struct fs_struct        *fs;

    /* Open file information: */
    struct files_struct     *files;

    struct io_uring_task    *io_uring;

    /* Namespaces: */
    struct nsproxy *nsproxy;

    /* Signal handlers: */
    struct signal_struct *signal;
    struct sighand_struct __rcu *sighand;
    sigset_t            blocked;
    struct sigpending   pending;

    unsigned long       sas_ss_sp;
    size_t              sas_ss_size;
    unsigned int        sas_ss_flags;

    struct callback_head *task_works;

    struct wake_q_node wake_q;

    /* PI waiters blocked on a rt_mutex held by this task: */
    struct rb_root_cached       pi_waiters;
    /* Updated under owner's pi_lock and rq lock */
    struct task_struct          *pi_top_task;
    /* Deadlock detection and priority inheritance handling: */
    struct rt_mutex_waiter      *pi_blocked_on;

    /* Protection of the PI data structures: */
    raw_spinlock_t pi_lock;

    /* VM state: */
    struct reclaim_state *reclaim_state;

    struct sched_entity     se;
    struct sched_rt_entity  rt;
    struct sched_dl_entity  dl;
    const struct sched_class *sched_class;

    int nr_cpus_allowed;
    const cpumask_t *cpus_ptr;
    cpumask_t *user_cpus_ptr;
    cpumask_t cpus_mask;

    void *migration_pending;

    unsigned short migration_disabled;
    unsigned short migration_flags;

    struct io_context   *io_context;

    struct capture_control *capture_control;

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

        /* disallow userland-initiated cgroup migration */
    unsigned            no_cgroup_migration:1;
    /* task is frozen/stopped (used by the cgroup freezer) */
    unsigned            frozen:1;

    /* CLONE_CHILD_SETTID: */
    int __user          *set_child_tid;

    /* CLONE_CHILD_CLEARTID: */
    int __user          *clear_child_tid;

    /* PF_KTHREAD | PF_IO_WORKER */
    void                *worker_private;

    int pagefault_disabled;

    pid_t               pid;
    pid_t               tgid;

    /* Empty if CONFIG_POSIX_CPUTIMERS=n */
    struct posix_cputimers      posix_cputimers;

    /*
     * When (nr_dirtied >= nr_dirtied_pause), it's time to call
     * balance_dirty_pages() for a dirty throttling pause:
     */
    int             nr_dirtied;
    int             nr_dirtied_pause;
    /* Start of a write-and-pause period: */
    unsigned long   dirty_paused_when;

    struct rseq __user *rseq;
    u32 rseq_sig;
    /*
     * RmW on rseq_event_mask must be performed atomically
     * with respect to preemption.
     */
    unsigned long rseq_event_mask;

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
    struct task_struct      *group_leader;

    /* Stacked block device info: */
    struct bio_list         *bio_list;

    /* Journalling filesystem info: */
    void                    *journal_info;

    /* Stack plugging: */
    struct blk_plug         *plug;

    struct prev_cputime     prev_cputime;

    /* Protection against (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed, mempolicy: */
    spinlock_t alloc_lock;

    /*
     * Time slack values; these are used to round up poll() and
     * select() etc timeout values. These are in nanoseconds.
     */
    u64 timer_slack_ns;
    u64 default_timer_slack_ns;

    /* Context switch counts: */
    unsigned long           nvcsw;
    unsigned long           nivcsw;

    /* Monotonic time in nsecs: */
    u64             start_time;

    /* Boot based time in nsecs: */
    u64             start_boottime;

    /* MM fault and swap info:
     * this can arguably be seen as either mm-specific or thread-specific: */
    unsigned long           min_flt;
    unsigned long           maj_flt;

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

extern void io_schedule(void);

extern struct root_domain def_root_domain;
extern struct mutex sched_domains_mutex;

/* Increase resolution of cpu_capacity calculations */
#define SCHED_CAPACITY_SHIFT    SCHED_FIXEDPOINT_SHIFT
#define SCHED_CAPACITY_SCALE    (1L << SCHED_CAPACITY_SHIFT)

extern unsigned long
wait_task_inactive(struct task_struct *, unsigned int match_state);

extern void do_set_cpus_allowed(struct task_struct *p,
                                const struct cpumask *new_mask);

extern struct task_struct *
find_task_by_pid_ns(pid_t nr, struct pid_namespace *ns);

extern int set_cpus_allowed_ptr(struct task_struct *p,
                                const struct cpumask *new_mask);

/**
 * is_idle_task - is the specified task an idle task?
 * @p: the task in question.
 *
 * Return: 1 if @p is an idle task. 0 otherwise.
 */
static __always_inline bool is_idle_task(const struct task_struct *p)
{
    return !!(p->flags & PF_IDLE);
}

static inline void
current_restore_flags(unsigned long orig_flags, unsigned long flags)
{
    current->flags &= ~flags;
    current->flags |= orig_flags & flags;
}

static inline void rseq_execve(struct task_struct *t)
{
    t->rseq = NULL;
    t->rseq_sig = 0;
    t->rseq_event_mask = 0;
}

/*
 * the helpers to get the task's different pids as they are seen
 * from various namespaces
 *
 * task_xid_nr()     : global id, i.e. the id seen from the init namespace;
 * task_xid_vnr()    : virtual id, i.e. the id seen from the pid namespace of
 *                     current.
 * task_xid_nr_ns()  : id seen from the ns specified;
 *
 * see also pid_nr() etc in include/linux/pid.h
 */
pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
                       struct pid_namespace *ns);

static inline pid_t
task_pid_nr_ns(struct task_struct *tsk, struct pid_namespace *ns)
{
    return __task_pid_nr_ns(tsk, PIDTYPE_PID, ns);
}

static inline pid_t task_pid_nr(struct task_struct *tsk)
{
    return tsk->pid;
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
    return test_ti_thread_flag(task_thread_info(tsk), flag);
}

extern int wake_up_state(struct task_struct *tsk, unsigned int state);

asmlinkage void schedule(void);

extern void
__set_task_comm(struct task_struct *tsk, const char *from, bool exec);

static inline
void set_task_comm(struct task_struct *tsk, const char *from)
{
    __set_task_comm(tsk, from, false);
}

static inline int test_tsk_need_resched(struct task_struct *tsk)
{
    return unlikely(test_tsk_thread_flag(tsk,TIF_NEED_RESCHED));
}

/*
 * Set thread flags in other task's structures.
 * See asm/thread_info.h for TIF_xxxx flags available:
 */
static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
    set_ti_thread_flag(task_thread_info(tsk), flag);
}

static inline void set_tsk_need_resched(struct task_struct *tsk)
{
    set_tsk_thread_flag(tsk, TIF_NEED_RESCHED);
}

extern int sched_setscheduler_nocheck(struct task_struct *, int,
                                      const struct sched_param *);

/**
 * task_nice - return the nice value of a given task.
 * @p: the task in question.
 *
 * Return: The nice value [ -20 ... 0 ... 19 ].
 */
static inline int task_nice(const struct task_struct *p)
{
    return PRIO_TO_NICE((p)->static_prio);
}

/*
 * set_special_state() should be used for those states when the blocking task
 * can not use the regular condition based wait-loop. In that case we must
 * serialize against wakeups such that any possible in-flight TASK_RUNNING
 * stores will not collide with our state change.
 */
#define set_special_state(state_value)                  \
    do {                                \
        unsigned long flags; /* may shadow */           \
                                    \
        raw_spin_lock_irqsave(&current->pi_lock, flags);    \
        WRITE_ONCE(current->__state, (state_value));        \
        raw_spin_unlock_irqrestore(&current->pi_lock, flags);   \
    } while (0)

static inline void rseq_set_notify_resume(struct task_struct *t)
{
    if (t->rseq)
        set_tsk_thread_flag(t, TIF_NOTIFY_RESUME);
}

/* rseq_preempt() requires preemption to be disabled. */
static inline void rseq_preempt(struct task_struct *t)
{
    __set_bit(RSEQ_EVENT_PREEMPT_BIT, &t->rseq_event_mask);
    rseq_set_notify_resume(t);
}

#endif /* _LINUX_SCHED_H */
