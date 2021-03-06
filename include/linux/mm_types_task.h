/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_TYPES_TASK_H
#define _LINUX_MM_TYPES_TASK_H

/*
 * Here are the definitions of the MM data types that are embedded in 'struct task_struct'.
 *
 * (These are defined separately to decouple sched.h from mm_types.h as much as possible.)
 */

#include <linux/types.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cpumask.h>

#include <asm/page.h>

#define USE_SPLIT_PTE_PTLOCKS (NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS)
#define USE_SPLIT_PMD_PTLOCKS (USE_SPLIT_PTE_PTLOCKS)

#define ALLOC_SPLIT_PTLOCKS (SPINLOCK_SIZE > BITS_PER_LONG/8)

#endif /* _LINUX_MM_TYPES_TASK_H */
