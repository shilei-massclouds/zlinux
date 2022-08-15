/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_SIGNAL_H
#define _LINUX_SCHED_SIGNAL_H

#include <linux/rculist.h>
#include <linux/signal.h>
#include <linux/sched.h>
/*
#include <linux/sched/jobctl.h>
*/
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/refcount.h>
//#include <linux/posix-timers.h>
#include <linux/mm_types.h>
#include <asm/ptrace.h>
#include <linux/ktime.h>

/*
 * Types defining task->signal and task->sighand and APIs using them:
 */

struct sighand_struct {
    spinlock_t      siglock;
    refcount_t      count;
    wait_queue_head_t   signalfd_wqh;
    struct k_sigaction  action[_NSIG];
};

/*
 * NOTE! "signal_struct" does not have its own
 * locking, because a shared signal_struct always
 * implies a shared sighand_struct, so locking
 * sighand_struct is always a proper superset of
 * the locking of signal_struct.
 */
struct signal_struct {
    refcount_t          sigcnt;
    atomic_t            live;
    int                 nr_threads;
    struct list_head    thread_head;

    wait_queue_head_t   wait_chldexit;  /* for wait4() */

    /* current thread group signal load-balancing target: */
    struct task_struct  *curr_target;

    /* shared signal handling: */
    struct sigpending   shared_pending;

    /* For collecting multiprocess signals during fork */
    struct hlist_head   multiprocess;

    /* thread group exit support */
    int group_exit_code;
    /* notify group_exec_task when notify_count is less or equal to 0 */
    int notify_count;
    struct task_struct  *group_exec_task;

    /* thread group stop support, overloads group_exit_code too */
    int                 group_stop_count;
    unsigned int        flags; /* see SIGNAL_* flags below */

    struct core_state *core_state; /* coredumping support */

    /*
     * PR_SET_CHILD_SUBREAPER marks a process, like a service
     * manager, to re-parent orphan (double-forking) child processes
     * to this process instead of 'init'. The service manager is
     * able to receive SIGCHLD signals and is able to investigate
     * the process until it calls wait(). All children of this
     * process will inherit a flag if they should look for a
     * child_subreaper process at exit.
     */
    unsigned int        is_child_subreaper:1;
    unsigned int        has_child_subreaper:1;

    /* POSIX.1b Interval Timers */
    int                 posix_timer_id;
    struct list_head    posix_timers;

#if 0
    /* ITIMER_REAL timer for the process */
    struct hrtimer real_timer;
    ktime_t it_real_incr;

    /*
     * ITIMER_PROF and ITIMER_VIRTUAL timers for the process, we use
     * CPUCLOCK_PROF and CPUCLOCK_VIRT for indexing array as these
     * values are defined to 0 and 1 respectively
     */
    struct cpu_itimer it[2];

    /*
     * Thread group totals for process CPU timers.
     * See thread_group_cputimer(), et al, for details.
     */
    struct thread_group_cputimer cputimer;

    /* Empty if CONFIG_POSIX_TIMERS=n */
    struct posix_cputimers posix_cputimers;
#endif

    /* PID/PID hash table linkage. */
    struct pid *pids[PIDTYPE_MAX];

    struct pid *tty_old_pgrp;

    /* boolean value for session group leader */
    int leader;

#if 0
    struct tty_struct *tty; /* NULL if no tty */
#endif

    /*
     * Cumulative resource counters for dead threads in the group,
     * and for reaped dead child processes forked by this group.
     * Live threads maintain their own counters and add to these
     * in __exit_signal, except for the group leader.
     */
    seqlock_t stats_lock;
    u64 utime, stime, cutime, cstime;
    u64 gtime;
    u64 cgtime;
#if 0
    struct prev_cputime prev_cputime;
#endif
    unsigned long nvcsw, nivcsw, cnvcsw, cnivcsw;
    unsigned long min_flt, maj_flt, cmin_flt, cmaj_flt;
    unsigned long inblock, oublock, cinblock, coublock;
    unsigned long maxrss, cmaxrss;
#if 0
    struct task_io_accounting ioac;
#endif

    /*
     * Cumulative ns of schedule CPU time fo dead threads in the
     * group, not including a zombie group leader, (This only differs
     * from jiffies_to_ns(utime + stime) if sched_clock uses something
     * other than jiffies.)
     */
    unsigned long long sum_sched_runtime;

    /*
     * We don't bother to synchronize most readers of this at all,
     * because there is no reader checking a limit that actually needs
     * to get both rlim_cur and rlim_max atomically, and either one
     * alone is a single word that can safely be read normally.
     * getrlimit/setrlimit use task_lock(current->group_leader) to
     * protect this instead of the siglock, because they really
     * have no need to disable irqs.
     */
    struct rlimit rlim[RLIM_NLIMITS];

    /*
     * Thread is the potential origin of an oom condition; kill first on
     * oom
     */
    bool oom_flag_origin;
    short oom_score_adj;        /* OOM kill score adjustment */
    short oom_score_adj_min;    /* OOM kill score adjustment min value.
                                 * Only settable by CAP_SYS_RESOURCE. */
    struct mm_struct *oom_mm;   /* recorded mm when the thread group got
                                 * killed by the oom killer */

    struct mutex cred_guard_mutex;  /* guard against foreign influences on
                                     * credential calculations
                                     * (notably. ptrace)
                                     * Deprecated do not use in new code.
                                     * Use exec_update_lock instead. */
    struct rw_semaphore exec_update_lock;   /* Held while task_struct is
                                             * being updated during exec,
                                             * and may have inconsistent
                                             * permissions. */
} __randomize_layout;

#define SIGNAL_UNKILLABLE   0x00000040 /* for init: ignore fatal signals */

static inline int signal_pending(struct task_struct *p)
{
#if 0
    /*
     * TIF_NOTIFY_SIGNAL isn't really a signal, but it requires the same
     * behavior in terms of ensuring that we break out of wait loops
     * so that notify signal callbacks can be processed.
     */
    if (unlikely(test_tsk_thread_flag(p, TIF_NOTIFY_SIGNAL)))
        return 1;
    return task_sigpending(p);
#endif
    panic("%s: END!\n", __func__);
    return 1;
}

static inline int
signal_pending_state(unsigned int state, struct task_struct *p)
{
    if (!(state & (TASK_INTERRUPTIBLE | TASK_WAKEKILL)))
        return 0;
    if (!signal_pending(p))
        return 0;

#if 0
    return (state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p);
#endif
    panic("%s: END!\n", __func__);
    return 0;
}

static inline bool thread_group_leader(struct task_struct *p)
{
    return p->exit_signal >= 0;
}

static inline int thread_group_empty(struct task_struct *p)
{
    return list_empty(&p->thread_group);
}

extern void flush_signal_handlers(struct task_struct *,
                                  int force_default);

static inline unsigned long task_rlimit(const struct task_struct *task,
                                        unsigned int limit)
{
    return READ_ONCE(task->signal->rlim[limit].rlim_cur);
}

static inline unsigned long task_rlimit_max(const struct task_struct *task,
                                            unsigned int limit)
{
    return READ_ONCE(task->signal->rlim[limit].rlim_max);
}

static inline unsigned long rlimit(unsigned int limit)
{
    return task_rlimit(current, limit);
}

static inline unsigned long rlimit_max(unsigned int limit)
{
    return task_rlimit_max(current, limit);
}

#endif /* _LINUX_SCHED_SIGNAL_H */
