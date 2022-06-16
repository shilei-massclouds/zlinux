// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

//#include <linux/kernel_stat.h>
#include <linux/mm.h>
/*
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/memremap.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
*/
#include <linux/export.h>
//#include <linux/delayacct.h>
#include <linux/init.h>
/*
#include <linux/pfn_t.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>
#include <linux/migrate.h>
*/
#include <linux/string.h>
/*
#include <linux/dma-debug.h>
#include <linux/debugfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/dax.h>
#include <linux/oom.h>
*/
#include <linux/numa.h>
/*
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/vmalloc.h>

#include <trace/events/kmem.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
*/
#include <asm/pgalloc.h>

#include "pgalloc-track.h"
#include "internal.h"

/* use the per-pgdat data instead for discontigmem - mbligh */
unsigned long max_mapnr;
EXPORT_SYMBOL(max_mapnr);

struct page *mem_map;
EXPORT_SYMBOL(mem_map);

/*
 * A number of key systems in x86 including ioremap() rely on the assumption
 * that high_memory defines the upper bound on direct map memory, then end
 * of ZONE_NORMAL.  Under CONFIG_DISCONTIG this means that max_low_pfn and
 * highstart_pfn must be the same; there must be no gap between ZONE_NORMAL
 * and ZONE_HIGHMEM.
 */
void *high_memory;
EXPORT_SYMBOL(high_memory);

unsigned long highest_memmap_pfn __read_mostly;

/*
 * Allocate p4d page table.
 * We've already handled the fast-path in-line.
 */
int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
    p4d_t *new = p4d_alloc_one(mm, address);
    if (!new)
        return -ENOMEM;

    spin_lock(&mm->page_table_lock);
    if (pgd_present(*pgd)) {    /* Another has populated it */
        p4d_free(mm, new);
    } else {
        smp_wmb(); /* See comment in pmd_install() */
        pgd_populate(mm, pgd, new);
    }
    spin_unlock(&mm->page_table_lock);
    return 0;
}

/*
 * Allocate page upper directory.
 * We've already handled the fast-path in-line.
 */
int __pud_alloc(struct mm_struct *mm, p4d_t *p4d, unsigned long address)
{
    pud_t *new = pud_alloc_one(mm, address);
    if (!new)
        return -ENOMEM;

    spin_lock(&mm->page_table_lock);
    if (!p4d_present(*p4d)) {
        mm_inc_nr_puds(mm);
        smp_wmb(); /* See comment in pmd_install() */
        p4d_populate(mm, p4d, new);
    } else  /* Another has populated it */
        pud_free(mm, new);
    spin_unlock(&mm->page_table_lock);
    return 0;
}

/*
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
    spinlock_t *ptl;
    pmd_t *new = pmd_alloc_one(mm, address);
    if (!new)
        return -ENOMEM;

    ptl = pud_lock(mm, pud);
    if (!pud_present(*pud)) {
        mm_inc_nr_pmds(mm);
        smp_wmb(); /* See comment in pmd_install() */
        pud_populate(mm, pud, new);
    } else {    /* Another has populated it */
        pmd_free(mm, new);
    }
    spin_unlock(ptl);
    return 0;
}

int __pte_alloc_kernel(pmd_t *pmd)
{
    pte_t *new = pte_alloc_one_kernel(&init_mm);
    if (!new)
        return -ENOMEM;

    spin_lock(&init_mm.page_table_lock);
    if (likely(pmd_none(*pmd))) {   /* Has another populated it ? */
        smp_wmb(); /* See comment in pmd_install() */
        pmd_populate_kernel(&init_mm, pmd, new);
        new = NULL;
    }
    spin_unlock(&init_mm.page_table_lock);
    if (new)
        pte_free_kernel(&init_mm, new);
    return 0;
}
