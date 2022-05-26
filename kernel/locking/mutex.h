/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Mutexes: blocking mutual exclusion locks
 *
 * started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 */

/*
 * This is the control structure for tasks blocked on mutex, which resides
 * on the blocked task's kernel stack:
 */
struct mutex_waiter {
    struct list_head        list;
    struct task_struct      *task;
    struct ww_acquire_ctx   *ww_ctx;
};
