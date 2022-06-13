/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KERNEL_STAT_H
#define _LINUX_KERNEL_STAT_H

#include <linux/smp.h>
#include <linux/threads.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
//#include <linux/interrupt.h>
#include <linux/sched.h>
#if 0
#include <linux/vtime.h>
#include <asm/irq.h>
#endif

extern unsigned long long nr_context_switches(void);

#endif /* _LINUX_KERNEL_STAT_H */
