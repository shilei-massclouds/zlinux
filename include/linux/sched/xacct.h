/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_XACCT_H
#define _LINUX_SCHED_XACCT_H

/*
 * Extended task accounting methods:
 */

#include <linux/sched.h>

static inline void add_rchar(struct task_struct *tsk, ssize_t amt)
{
}

static inline void add_wchar(struct task_struct *tsk, ssize_t amt)
{
}

static inline void inc_syscr(struct task_struct *tsk)
{
}

static inline void inc_syscw(struct task_struct *tsk)
{
}

#endif /* _LINUX_SCHED_XACCT_H */
