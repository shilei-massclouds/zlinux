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

/*
 * The per task VMA cache array:
 */
#define VMACACHE_BITS 2
#define VMACACHE_SIZE (1U << VMACACHE_BITS)
#define VMACACHE_MASK (VMACACHE_SIZE - 1)


/*
 * When updating this, please also update struct resident_page_types[] in
 * kernel/fork.c
 */
enum {
    MM_FILEPAGES,   /* Resident file mapping pages */
    MM_ANONPAGES,   /* Resident anonymous pages */
    MM_SWAPENTS,    /* Anonymous swap entries */
    MM_SHMEMPAGES,  /* Resident shared memory pages */
    NR_MM_COUNTERS
};

struct vmacache {
    u64 seqnum;
    struct vm_area_struct *vmas[VMACACHE_SIZE];
};

#endif /* _LINUX_MM_TYPES_TASK_H */
