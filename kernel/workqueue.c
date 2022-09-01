// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/workqueue.c - generic async execution with shared worker pool
 *
 * Copyright (C) 2002       Ingo Molnar
 *
 *   Derived from the taskqueue/keventd code by:
 *     David Woodhouse <dwmw2@infradead.org>
 *     Andrew Morton
 *     Kai Petzke <wpp@marie.physik.tu-berlin.de>
 *     Theodore Ts'o <tytso@mit.edu>
 *
 * Made to use alloc_percpu by Christoph Lameter.
 *
 * Copyright (C) 2010       SUSE Linux Products GmbH
 * Copyright (C) 2010       Tejun Heo <tj@kernel.org>
 *
 * This is the generic async execution mechanism.  Work items as are
 * executed in process context.  The worker pool is shared and
 * automatically managed.  There are two worker pools for each CPU (one for
 * normal work items and the other for high priority ones) and some extra
 * pools for workqueues which are not bound to any specific CPU - the
 * number of these backing pools is dynamic.
 *
 * Please read Documentation/core-api/workqueue.rst for details.
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/cpu.h>
//#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/hardirq.h>
#include <linux/mempolicy.h>
#if 0
#include <linux/freezer.h>
#include <linux/debug_locks.h>
#endif
#include <linux/lockdep.h>
#include <linux/idr.h>
//#include <linux/jhash.h>
#include <linux/hashtable.h>
#include <linux/rculist.h>
#include <linux/nodemask.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/sched/isolation.h>
#if 0
#include <linux/nmi.h>
#include <linux/kvm_para.h>
#endif

//#include "workqueue_internal.h"

void delayed_work_timer_fn(struct timer_list *t)
{
#if 0
    struct delayed_work *dwork = from_timer(dwork, t, timer);

    /* should have been called from irqsafe timer with irq already off */
    __queue_work(dwork->cpu, dwork->wq, &dwork->work);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(delayed_work_timer_fn);
