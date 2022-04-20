/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PERCPU_H
#define __LINUX_PERCPU_H

//#include <linux/mmdebug.h>
#include <linux/preempt.h>
#include <linux/smp.h>
//#include <linux/cpumask.h>
#include <linux/printk.h>
#include <linux/pfn.h>
#include <linux/init.h>

#include <asm/percpu.h>

extern void __init setup_per_cpu_areas(void);

#endif /* __LINUX_PERCPU_H */
