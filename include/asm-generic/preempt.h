/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_PREEMPT_H
#define __ASM_PREEMPT_H

#include <linux/thread_info.h>

#define PREEMPT_ENABLED (0)

static __always_inline volatile int *preempt_count_ptr(void)
{
    return &current_thread_info()->preempt_count;
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

#endif /* __ASM_PREEMPT_H */
