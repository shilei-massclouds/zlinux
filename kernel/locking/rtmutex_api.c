// SPDX-License-Identifier: GPL-2.0-only
/*
 * rtmutex API
 */
#include <linux/spinlock.h>
#include <linux/export.h>

#define RT_MUTEX_BUILD_MUTEX
#include "rtmutex.c"

/*
 * Recheck the pi chain, in case we got a priority setting
 *
 * Called from sched_setscheduler
 */
void __sched rt_mutex_adjust_pi(struct task_struct *task)
{
    struct rt_mutex_waiter *waiter;
    struct rt_mutex_base *next_lock;
    unsigned long flags;

    raw_spin_lock_irqsave(&task->pi_lock, flags);

    waiter = task->pi_blocked_on;
    if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task))) {
        raw_spin_unlock_irqrestore(&task->pi_lock, flags);
        return;
    }
    next_lock = waiter->lock;
    raw_spin_unlock_irqrestore(&task->pi_lock, flags);

    panic("%s: END!\n", __func__);
}
