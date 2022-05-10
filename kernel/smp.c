// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic helpers for smp ipi calls
 *
 * (C) Jens Axboe <jens.axboe@oracle.com> 2008
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/*
#include <linux/irq_work.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
*/
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/init.h>
//#include <linux/interrupt.h>
#include <linux/gfp.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/sched.h>
/*
#include <linux/sched/idle.h>
#include <linux/hypervisor.h>
#include <linux/sched/clock.h>
#include <linux/nmi.h>
*/
#include <linux/sched/debug.h>
//#include <linux/jump_label.h>

//#include "smpboot.h"
//#include "sched/smp.h"

/* Setup number of possible processor ids */
unsigned int nr_cpu_ids __read_mostly = NR_CPUS;
EXPORT_SYMBOL(nr_cpu_ids);
