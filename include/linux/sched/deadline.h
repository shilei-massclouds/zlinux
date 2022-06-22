/* SPDX-License-Identifier: GPL-2.0 */

/*
 * SCHED_DEADLINE tasks has negative priorities, reflecting
 * the fact that any of them has higher prio than RT and
 * NORMAL/BATCH tasks.
 */

#include <linux/sched.h>

#define MAX_DL_PRIO     0

static inline int dl_prio(int prio)
{
    if (unlikely(prio < MAX_DL_PRIO))
        return 1;
    return 0;
}
