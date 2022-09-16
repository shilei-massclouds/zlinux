/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TASK_WORK_H
#define _LINUX_TASK_WORK_H

#include <linux/list.h>
#include <linux/sched.h>

typedef void (*task_work_func_t)(struct callback_head *);

static inline void
init_task_work(struct callback_head *twork, task_work_func_t func)
{
    twork->func = func;
}

enum task_work_notify_mode {
    TWA_NONE,
    TWA_RESUME,
    TWA_SIGNAL,
};

static inline bool task_work_pending(struct task_struct *task)
{
    return READ_ONCE(task->task_works);
}

void task_work_run(void);

#endif  /* _LINUX_TASK_WORK_H */
