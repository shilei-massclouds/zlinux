// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <asm/sbi.h>
#include <asm/mmu_context.h>

void flush_tlb_all(void)
{
    sbi_remote_sfence_vma(NULL, 0, -1);
}

static void __sbi_tlb_flush_range(struct mm_struct *mm, unsigned long start,
                  unsigned long size, unsigned long stride)
{
    struct cpumask *cmask = mm_cpumask(mm);
    unsigned int cpuid;
    bool broadcast;

    if (cpumask_empty(cmask))
        return;

    cpuid = get_cpu();
    /* check if the tlbflush needs to be sent to other CPUs */
    broadcast = cpumask_any_but(cmask, cpuid) < nr_cpu_ids;
    if (static_branch_unlikely(&use_asid_allocator)) {
#if 0
        unsigned long asid = atomic_long_read(&mm->context.id);

        if (broadcast) {
            sbi_remote_sfence_vma_asid(cmask, start, size, asid);
        } else if (size <= stride) {
            local_flush_tlb_page_asid(start, asid);
        } else {
            local_flush_tlb_all_asid(asid);
        }
#endif
    } else {
        if (broadcast) {
            sbi_remote_sfence_vma(cmask, start, size);
        } else if (size <= stride) {
            local_flush_tlb_page(start);
        } else {
            local_flush_tlb_all();
        }
    }

    put_cpu();
    panic("%s: END!\n", __func__);
}

void flush_tlb_range(struct vm_area_struct *vma,
                     unsigned long start, unsigned long end)
{
    __sbi_tlb_flush_range(vma->vm_mm, start, end - start, PAGE_SIZE);
}
