/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KTHREAD_H
#define _LINUX_KTHREAD_H
/* Simple interface for creating and stopping kernel threads without mess. */
#include <linux/err.h>
#include <linux/sched.h>

extern int tsk_fork_get_node(struct task_struct *tsk);

#endif /* _LINUX_KTHREAD_H */
