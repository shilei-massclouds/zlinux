/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RT Mutexes: blocking mutual exclusion locks with PI support
 *
 * started by Ingo Molnar and Thomas Gleixner:
 *
 *  Copyright (C) 2004-2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *  Copyright (C) 2006, Timesys Corp., Thomas Gleixner <tglx@timesys.com>
 *
 * This file contains the private data structure and API definitions.
 */

#ifndef __KERNEL_RTMUTEX_COMMON_H
#define __KERNEL_RTMUTEX_COMMON_H

//#include <linux/debug_locks.h>
//#include <linux/rtmutex.h>
#include <linux/sched/wake_q.h>

/*
 * This is the control structure for tasks blocked on a rt_mutex,
 * which is allocated on the kernel stack on of the blocked task.
 *
 * @tree_entry:     pi node to enqueue into the mutex waiters tree
 * @pi_tree_entry:  pi node to enqueue into the mutex owner waiters tree
 * @task:       task reference to the blocked task
 * @lock:       Pointer to the rt_mutex on which the waiter blocks
 * @wake_state:     Wakeup state to use (TASK_NORMAL or TASK_RTLOCK_WAIT)
 * @prio:       Priority of the waiter
 * @deadline:       Deadline of the waiter if applicable
 * @ww_ctx:     WW context pointer
 */
struct rt_mutex_waiter {
    struct rb_node      tree_entry;
    struct rb_node      pi_tree_entry;
    struct task_struct  *task;
    struct rt_mutex_base    *lock;
    unsigned int        wake_state;
    int         prio;
    u64         deadline;
    struct ww_acquire_ctx   *ww_ctx;
};

#endif /* __KERNEL_RTMUTEX_COMMON_H */
