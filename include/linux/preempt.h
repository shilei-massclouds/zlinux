/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PREEMPT_H
#define __LINUX_PREEMPT_H

/*
 * include/linux/preempt.h - macros for accessing and manipulating
 * preempt_count (used for kernel preemption, interrupt count, etc.)
 */

#include <linux/linkage.h>

#define PREEMPT_SHIFT   0

#define PREEMPT_OFFSET  (1UL << PREEMPT_SHIFT)

/*
 * Disable preemption until the scheduler is running -- use an unconditional
 * value so that it also works on !PREEMPT_COUNT kernels.
 *
 * Reset by start_kernel()->sched_init()->init_idle()->init_idle_preempt_count().
 */
#define INIT_PREEMPT_COUNT  PREEMPT_OFFSET

/* preempt_count() and related functions, depends on PREEMPT_NEED_RESCHED */
#include <asm/preempt.h>

#define preempt_count_add(val)  __preempt_count_add(val)
#define preempt_count_sub(val)  __preempt_count_sub(val)

#define preempt_count_inc() preempt_count_add(1)
#define preempt_count_dec() preempt_count_sub(1)

#define preempt_enable() \
do { \
    barrier(); \
    preempt_count_dec(); \
} while (0)

#define preempt_disable() \
do { \
    preempt_count_inc(); \
    barrier(); \
} while (0)

#endif /* __LINUX_PREEMPT_H */
