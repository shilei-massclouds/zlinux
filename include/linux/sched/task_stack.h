/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_TASK_STACK_H
#define _LINUX_SCHED_TASK_STACK_H

/*
 * task->stack (kernel stack) handling interfaces:
 */

#include <linux/sched.h>
#include <linux/magic.h>

/*
 * When accessing the stack of a non-current task that might exit, use
 * try_get_task_stack() instead.  task_stack_page will return a pointer
 * that could get freed out from under you.
 */
static inline void *task_stack_page(const struct task_struct *task)
{
    return task->stack;
}

#define setup_thread_stack(new,old) do { } while(0)

static inline unsigned long *end_of_stack(const struct task_struct *task)
{
    return task->stack;
}

extern void set_task_stack_end_magic(struct task_struct *tsk);

extern void put_task_stack(struct task_struct *tsk);

#endif /* _LINUX_SCHED_TASK_STACK_H */
