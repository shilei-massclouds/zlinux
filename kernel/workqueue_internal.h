/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel/workqueue_internal.h
 *
 * Workqueue internal header file.  Only to be included by workqueue and
 * core kernel subsystems.
 */
#ifndef _KERNEL_WORKQUEUE_INTERNAL_H
#define _KERNEL_WORKQUEUE_INTERNAL_H

#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/preempt.h>

struct worker_pool;

/*
 * Scheduler hooks for concurrency managed workqueue.  Only to be used from
 * sched/ and workqueue.c.
 */
void wq_worker_running(struct task_struct *task);
void wq_worker_sleeping(struct task_struct *task);
work_func_t wq_worker_last_func(struct task_struct *task);

#endif /* _KERNEL_WORKQUEUE_INTERNAL_H */
