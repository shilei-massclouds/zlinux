/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_PREEMPT_H
#define __ASM_PREEMPT_H

#include <linux/thread_info.h>

#define PREEMPT_ENABLED (0)

static __always_inline int preempt_count(void)
{
    return READ_ONCE(current_thread_info()->preempt_count);
}

static __always_inline volatile int *preempt_count_ptr(void)
{
    return &current_thread_info()->preempt_count;
}

static __always_inline void preempt_count_set(int pc)
{
    *preempt_count_ptr() = pc;
}

/*
 * The various preempt_count add/sub methods
 */

static __always_inline void __preempt_count_add(int val)
{
    *preempt_count_ptr() += val;
}

static __always_inline void __preempt_count_sub(int val)
{
    *preempt_count_ptr() -= val;
}

/*
 * must be macros to avoid header recursion hell
 */
#define init_task_preempt_count(p) do { \
    task_thread_info(p)->preempt_count = FORK_PREEMPT_COUNT; \
} while (0)

#define init_idle_preempt_count(p, cpu) do { \
    task_thread_info(p)->preempt_count = PREEMPT_DISABLED; \
} while (0)

static __always_inline void set_preempt_need_resched(void)
{
}

#endif /* __ASM_PREEMPT_H */
