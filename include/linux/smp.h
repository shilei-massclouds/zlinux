/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SMP_H
#define __LINUX_SMP_H

/*
 *  Generic SMP support
 *      Alan Cox. <alan@redhat.com>
 */

#include <linux/errno.h>
#include <linux/types.h>
//#include <linux/list.h>
#include <linux/cpumask.h>
#include <linux/init.h>
//#include <linux/smp_types.h>

#include <linux/preempt.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/thread_info.h>
#include <asm/smp.h>

/*
 * Allow the architecture to differentiate between a stable and unstable read.
 * For example, x86 uses an IRQ-safe asm-volatile read for the unstable but a
 * regular asm read for the stable.
 */
#ifndef __smp_processor_id
#define __smp_processor_id(x) raw_smp_processor_id(x)
#endif

#define smp_processor_id() __smp_processor_id()

#endif /* __LINUX_SMP_H */