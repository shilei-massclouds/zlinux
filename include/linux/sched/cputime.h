/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_CPUTIME_H
#define _LINUX_SCHED_CPUTIME_H

#include <linux/sched/signal.h>

/*
 * cputime accounting APIs:
 */

static inline void prev_cputime_init(struct prev_cputime *prev)
{
    prev->utime = prev->stime = 0;
    raw_spin_lock_init(&prev->lock);
}

#endif /* _LINUX_SCHED_CPUTIME_H */
