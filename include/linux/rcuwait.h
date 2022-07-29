/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RCUWAIT_H_
#define _LINUX_RCUWAIT_H_

#include <linux/rcupdate.h>
#include <linux/sched/signal.h>

/*
 * rcuwait provides a way of blocking and waking up a single
 * task in an rcu-safe manner.
 *
 * The only time @task is non-nil is when a user is blocked (or
 * checking if it needs to) on a condition, and reset as soon as we
 * know that the condition has succeeded and are awoken.
 */
struct rcuwait {
    struct task_struct __rcu *task;
};

#define __RCUWAIT_INITIALIZER(name) \
    { .task = NULL, }

static inline void rcuwait_init(struct rcuwait *w)
{
    w->task = NULL;
}

#endif /* _LINUX_RCUWAIT_H_ */
