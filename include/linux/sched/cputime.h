/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_CPUTIME_H
#define _LINUX_SCHED_CPUTIME_H

#include <linux/sched/signal.h>

/*
 * cputime accounting APIs:
 */

static inline void prev_cputime_init(struct prev_cputime *prev)
{
    prev->utime = prev->stime = 0;
    raw_spin_lock_init(&prev->lock);
}

static inline
struct thread_group_cputimer *
get_running_cputimer(struct task_struct *tsk)
{
    struct thread_group_cputimer *cputimer = &tsk->signal->cputimer;

    /*
     * Check whether posix CPU timers are active. If not the thread
     * group accounting is not active either. Lockless check.
     */
    if (!READ_ONCE(tsk->signal->posix_cputimers.timers_active))
        return NULL;

    panic("%s: END!\n", __func__);
}

/**
 * account_group_exec_runtime - Maintain exec runtime for a thread group.
 *
 * @tsk:    Pointer to task structure.
 * @ns:     Time value by which to increment the sum_exec_runtime field
 *      of the thread_group_cputime structure.
 *
 * If thread group time is being maintained, get the structure for the
 * running CPU and update the sum_exec_runtime field there.
 */
static inline
void account_group_exec_runtime(struct task_struct *tsk,
                                unsigned long long ns)
{
    struct thread_group_cputimer *cputimer = get_running_cputimer(tsk);

    if (!cputimer)
        return;

    atomic64_add(ns, &cputimer->cputime_atomic.sum_exec_runtime);
}

#endif /* _LINUX_SCHED_CPUTIME_H */
