// SPDX-License-Identifier: GPL-2.0-only
/*
 * RT-Mutexes: simple blocking mutual exclusion locks with PI support
 *
 * started by Ingo Molnar and Thomas Gleixner.
 *
 *  Copyright (C) 2004-2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *  Copyright (C) 2005-2006 Timesys Corp., Thomas Gleixner <tglx@timesys.com>
 *  Copyright (C) 2005 Kihon Technologies Inc., Steven Rostedt
 *  Copyright (C) 2006 Esben Nielsen
 * Adaptive Spinlocks:
 *  Copyright (C) 2008 Novell, Inc., Gregory Haskins, Sven Dietrich,
 *                   and Peter Morreale,
 * Adaptive Spinlocks simplification:
 *  Copyright (C) 2008 Red Hat, Inc., Steven Rostedt <srostedt@redhat.com>
 *
 *  See Documentation/locking/rt-mutex-design.rst for details.
 */
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/deadline.h>
#include <linux/sched/signal.h>
#include <linux/sched/rt.h>
#include <linux/sched/wake_q.h>
#include <linux/ww_mutex.h>

#include "rtmutex_common.h"

static __always_inline int __waiter_prio(struct task_struct *task)
{
    int prio = task->prio;

    if (!rt_prio(prio))
        return DEFAULT_PRIO;

    return prio;
}

/*
 * Only use with rt_mutex_waiter_{less,equal}()
 */
#define task_to_waiter(p)   \
    &(struct rt_mutex_waiter){ \
        .prio = __waiter_prio(p), \
        .deadline = (p)->dl.deadline \
    }

static __always_inline
int rt_mutex_waiter_equal(struct rt_mutex_waiter *left,
                          struct rt_mutex_waiter *right)
{
    if (left->prio != right->prio)
        return 0;

    /*
     * If both waiters have dl_prio(), we check the deadlines of the
     * associated tasks.
     * If left waiter has a dl_prio(), and we didn't return 0 above,
     * then right waiter has a dl_prio() too.
     */
    if (dl_prio(left->prio))
        return left->deadline == right->deadline;

    return 1;
}
