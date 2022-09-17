// SPDX-License-Identifier: GPL-2.0
/*
 * Implement CPU time clocks for the POSIX clock interface.
 */

#include <linux/sched/signal.h>
#include <linux/sched/cputime.h>
#include <linux/posix-timers.h>
#include <linux/errno.h>
#include <linux/math64.h>
#include <linux/uaccess.h>
#include <linux/kernel_stat.h>
#include <linux/tick.h>
#include <linux/workqueue.h>
#include <linux/compat.h>
#include <linux/sched/deadline.h>
#include <linux/task_work.h>

//#include "posix-timers.h"

void posix_cputimers_group_init(struct posix_cputimers *pct, u64 cpu_limit)
{
    posix_cputimers_init(pct);
    if (cpu_limit != RLIM_INFINITY) {
        pct->bases[CPUCLOCK_PROF].nextevt = cpu_limit * NSEC_PER_SEC;
        pct->timers_active = true;
    }
}
