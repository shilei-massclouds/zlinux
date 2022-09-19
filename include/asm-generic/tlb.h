/* SPDX-License-Identifier: GPL-2.0-or-later */
/* include/asm-generic/tlb.h
 *
 *  Generic TLB shootdown code
 *
 * Copyright 2001 Red Hat, Inc.
 * Based on code from mm/memory.c Copyright Linus Torvalds and others.
 *
 * Copyright 2011 Red Hat, Inc., Peter Zijlstra
 */
#ifndef _ASM_GENERIC__TLB_H
#define _ASM_GENERIC__TLB_H

#include <linux/mmu_notifier.h>
#include <linux/swap.h>
#include <linux/hugetlb_inline.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>

/*
 * If we can't allocate a page to make a big batch of page pointers
 * to work on, then just handle a few from the on-stack structure.
 */
#define MMU_GATHER_BUNDLE   8

struct mmu_gather_batch {
    struct mmu_gather_batch *next;
    unsigned int nr;
    unsigned int max;
    struct page *pages[];
};

/*
 * struct mmu_gather is an opaque type used by the mm code for passing around
 * any data needed by arch specific code for tlb_remove_page.
 */
struct mmu_gather {
    struct mm_struct    *mm;

    unsigned long       start;
    unsigned long       end;
    /*
     * we are in the middle of an operation to clear
     * a full mm and can make some optimizations
     */
    unsigned int        fullmm : 1;

    /*
     * we have performed an operation which
     * requires a complete flush of the tlb
     */
    unsigned int        need_flush_all : 1;

    /*
     * we have removed page directories
     */
    unsigned int        freed_tables : 1;

    /*
     * at which levels have we cleared entries?
     */
    unsigned int        cleared_ptes : 1;
    unsigned int        cleared_pmds : 1;
    unsigned int        cleared_puds : 1;
    unsigned int        cleared_p4ds : 1;

    /*
     * tracks VM_EXEC | VM_HUGETLB in tlb_start_vma
     */
    unsigned int        vma_exec : 1;
    unsigned int        vma_huge : 1;

    unsigned int        batch_count;

    struct mmu_gather_batch *active;
    struct mmu_gather_batch local;
    struct page     *__pages[MMU_GATHER_BUNDLE];
};

static inline void
tlb_update_vma_flags(struct mmu_gather *tlb, struct vm_area_struct *vma){
}

static inline void __tlb_reset_range(struct mmu_gather *tlb)
{
    if (tlb->fullmm) {
        tlb->start = tlb->end = ~0;
    } else {
        tlb->start = TASK_SIZE;
        tlb->end = 0;
    }
    tlb->freed_tables = 0;
    tlb->cleared_ptes = 0;
    tlb->cleared_pmds = 0;
    tlb->cleared_puds = 0;
    tlb->cleared_p4ds = 0;
    /*
     * Do not reset mmu_gather::vma_* fields here, we do not
     * call into tlb_start_vma() again to set them if there is an
     * intermediate flush.
     */
}

static inline void tlb_change_page_size(struct mmu_gather *tlb,
                                        unsigned int page_size)
{
}

static inline void tlb_remove_page_size(struct mmu_gather *tlb,
                                        struct page *page, int page_size)
{
#if 0
    if (__tlb_remove_page_size(tlb, page, page_size))
        tlb_flush_mmu(tlb);
#endif
    panic("%s: END!\n", __func__);
}

/* tlb_remove_page
 *  Similar to __tlb_remove_page but will call tlb_flush_mmu() itself when
 *  required.
 */
static inline void tlb_remove_page(struct mmu_gather *tlb, struct page *page)
{
    return tlb_remove_page_size(tlb, page, PAGE_SIZE);
}

static inline void __tlb_adjust_range(struct mmu_gather *tlb,
                                      unsigned long address,
                                      unsigned int range_size)
{
    tlb->start = min(tlb->start, address);
    tlb->end = max(tlb->end, address + range_size);
}

static inline void tlb_flush_pmd_range(struct mmu_gather *tlb,
                                       unsigned long address,
                                       unsigned long size)
{
    __tlb_adjust_range(tlb, address, size);
    tlb->cleared_pmds = 1;
}

static inline void tlb_flush_pud_range(struct mmu_gather *tlb,
                                       unsigned long address,
                                       unsigned long size)
{
    __tlb_adjust_range(tlb, address, size);
    tlb->cleared_puds = 1;
}

static inline void tlb_flush_p4d_range(struct mmu_gather *tlb,
                                       unsigned long address,
                                       unsigned long size)
{
    __tlb_adjust_range(tlb, address, size);
    tlb->cleared_p4ds = 1;
}

/*
 * For things like page tables caches (ie caching addresses "inside" the
 * page tables, like x86 does), for legacy reasons, flushing an
 * individual page had better flush the page table caches behind it. This
 * is definitely how x86 works, for example. And if you have an
 * architected non-legacy page table cache (which I'm not aware of
 * anybody actually doing), you're going to have some architecturally
 * explicit flushing for that, likely *separate* from a regular TLB entry
 * flush, and thus you'd need more than just some range expansion..
 *
 * So if we ever find an architecture
 * that would want something that odd, I think it is up to that
 * architecture to do its own odd thing, not cause pain for others
 * http://lkml.kernel.org/r/CA+55aFzBggoXtNXQeng5d_mRoDnaMBE5Y+URs+PHR67nUpMtaw@mail.gmail.com
 *
 * For now w.r.t page table cache, mark the range_size as PAGE_SIZE
 */

#ifndef pte_free_tlb
#define pte_free_tlb(tlb, ptep, address)            \
    do {                            \
        tlb_flush_pmd_range(tlb, address, PAGE_SIZE);   \
        tlb->freed_tables = 1;              \
        __pte_free_tlb(tlb, ptep, address);     \
    } while (0)
#endif

#ifndef pmd_free_tlb
#define pmd_free_tlb(tlb, pmdp, address)            \
    do {                            \
        tlb_flush_pud_range(tlb, address, PAGE_SIZE);   \
        tlb->freed_tables = 1;              \
        __pmd_free_tlb(tlb, pmdp, address);     \
    } while (0)
#endif

#ifndef pud_free_tlb
#define pud_free_tlb(tlb, pudp, address)            \
    do {                            \
        tlb_flush_p4d_range(tlb, address, PAGE_SIZE);   \
        tlb->freed_tables = 1;              \
        __pud_free_tlb(tlb, pudp, address);     \
    } while (0)
#endif

#ifndef p4d_free_tlb
#define p4d_free_tlb(tlb, pudp, address)            \
    do {                            \
        __tlb_adjust_range(tlb, address, PAGE_SIZE);    \
        tlb->freed_tables = 1;              \
        __p4d_free_tlb(tlb, pudp, address);     \
    } while (0)
#endif

static inline void tlb_flush_mmu_tlbonly(struct mmu_gather *tlb)
{
    /*
     * Anything calling __tlb_adjust_range() also sets at least one of
     * these bits.
     */
    if (!(tlb->freed_tables || tlb->cleared_ptes || tlb->cleared_pmds ||
          tlb->cleared_puds || tlb->cleared_p4ds))
        return;

    tlb_flush(tlb);
    mmu_notifier_invalidate_range(tlb->mm, tlb->start, tlb->end);
    __tlb_reset_range(tlb);
}

/*
 * In the case of tlb vma handling, we can optimise these away in the
 * case where we're doing a full MM flush.  When we're doing a munmap,
 * the vmas are adjusted to only cover the region to be torn down.
 */
#ifndef tlb_start_vma
static inline
void tlb_start_vma(struct mmu_gather *tlb, struct vm_area_struct *vma)
{
    if (tlb->fullmm)
        return;

    tlb_update_vma_flags(tlb, vma);
    flush_cache_range(vma, vma->vm_start, vma->vm_end);
}
#endif

#ifndef tlb_end_vma
static inline
void tlb_end_vma(struct mmu_gather *tlb, struct vm_area_struct *vma)
{
    if (tlb->fullmm)
        return;

    /*
     * Do a TLB flush and reset the range at VMA boundaries; this avoids
     * the ranges growing with the unused space between consecutive VMAs,
     * but also the mmu_gather::vma_* flags from tlb_start_vma() rely on
     * this.
     */
    tlb_flush_mmu_tlbonly(tlb);
}
#endif

void tlb_flush_mmu(struct mmu_gather *tlb);

#endif /* _ASM_GENERIC__TLB_H */
