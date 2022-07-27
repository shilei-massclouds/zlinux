// SPDX-License-Identifier: GPL-2.0+
/*
 * Sleepable Read-Copy Update mechanism for mutual exclusion.
 *
 * Copyright (C) IBM Corporation, 2006
 * Copyright (C) Fujitsu, 2012
 *
 * Authors: Paul McKenney <paulmck@linux.ibm.com>
 *     Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 *      Documentation/RCU/ *.txt
 *
 */

#define pr_fmt(fmt) "rcu: " fmt

#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
//#include <linux/rcupdate_wait.h>
#include <linux/sched.h>
#include <linux/smp.h>
//#include <linux/delay.h>
#include <linux/module.h>
#include <linux/srcu.h>

#include "rcu.h"
//#include "rcu_segcblist.h"

/*
 * Counts the new reader in the appropriate per-CPU element of the
 * srcu_struct.
 * Returns an index that must be passed to the matching srcu_read_unlock().
 */
int __srcu_read_lock(struct srcu_struct *ssp)
{
#if 0
    int idx;

    idx = READ_ONCE(ssp->srcu_idx) & 0x1;
    this_cpu_inc(ssp->sda->srcu_lock_count[idx]);
    smp_mb(); /* B */  /* Avoid leaking the critical section. */
    return idx;
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(__srcu_read_lock);

/*
 * Removes the count for the old reader from the appropriate per-CPU
 * element of the srcu_struct.  Note that this may well be a different
 * CPU than that which was incremented by the corresponding srcu_read_lock().
 */
void __srcu_read_unlock(struct srcu_struct *ssp, int idx)
{
#if 0
    smp_mb(); /* C */  /* Avoid leaking the critical section. */
    this_cpu_inc(ssp->sda->srcu_unlock_count[idx]);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(__srcu_read_unlock);
