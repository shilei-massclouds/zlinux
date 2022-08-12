// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 */

#include <linux/bitops.h>
#include <linux/cpumask.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
//#include <linux/static_key.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>

DEFINE_STATIC_KEY_FALSE(use_asid_allocator);

static void set_mm_asid(struct mm_struct *mm, unsigned int cpu)
{
    panic("%s: END!\n", __func__);
}

static void set_mm_noasid(struct mm_struct *mm)
{
    /* Switch the page table and blindly nuke entire local TLB */
    csr_write(CSR_SATP, virt_to_pfn(mm->pgd) | satp_mode);
    local_flush_tlb_all();
}

static inline void set_mm(struct mm_struct *mm, unsigned int cpu)
{
    if (static_branch_unlikely(&use_asid_allocator))
        set_mm_asid(mm, cpu);
    else
        set_mm_noasid(mm);
}

/*
 * When necessary, performs a deferred icache flush for the given MM context,
 * on the local CPU.  RISC-V has no direct mechanism for instruction cache
 * shoot downs, so instead we send an IPI that informs the remote harts they
 * need to flush their local instruction caches.  To avoid pathologically slow
 * behavior in a common case (a bunch of single-hart processes on a many-hart
 * machine, ie 'make -j') we avoid the IPIs for harts that are not currently
 * executing a MM context and instead schedule a deferred local instruction
 * cache flush to be performed before execution resumes on each hart.  This
 * actually performs that local instruction cache flush, which implicitly only
 * refers to the current hart.
 *
 * The "cpu" argument must be the current local CPU number.
 */
static inline void flush_icache_deferred(struct mm_struct *mm,
                                         unsigned int cpu)
{
    cpumask_t *mask = &mm->context.icache_stale_mask;

    if (cpumask_test_cpu(cpu, mask)) {
        cpumask_clear_cpu(cpu, mask);
        /*
         * Ensure the remote hart's writes are visible to this hart.
         * This pairs with a barrier in flush_icache_mm.
         */
        smp_mb();
        local_flush_icache_all();
    }
}

void switch_mm(struct mm_struct *prev, struct mm_struct *next,
               struct task_struct *task)
{
    unsigned int cpu;

    if (unlikely(prev == next))
        return;

    /*
     * Mark the current MM context as inactive, and the next as
     * active.  This is at least used by the icache flushing
     * routines in order to determine who should be flushed.
     */
    cpu = smp_processor_id();

    cpumask_clear_cpu(cpu, mm_cpumask(prev));
    cpumask_set_cpu(cpu, mm_cpumask(next));

    set_mm(next, cpu);

    flush_icache_deferred(next, cpu);
}
