#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mmdebug.h>
#include <linux/mm_types.h>
#include <linux/mm_inline.h>
#include <linux/pagemap.h>
#include <linux/rcupdate.h>
#include <linux/smp.h>
#include <linux/swap.h>

#include <asm/pgalloc.h>
#include <asm/tlb.h>

static void __tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm,
                             bool fullmm)
{
    tlb->mm = mm;
    tlb->fullmm = fullmm;

    tlb->need_flush_all = 0;
    tlb->local.next = NULL;
    tlb->local.nr   = 0;
    tlb->local.max  = ARRAY_SIZE(tlb->__pages);
    tlb->active     = &tlb->local;
    tlb->batch_count = 0;

    __tlb_reset_range(tlb);
    inc_tlb_flush_pending(tlb->mm);
}

/**
 * tlb_gather_mmu - initialize an mmu_gather structure for page-table tear-down
 * @tlb: the mmu_gather structure to initialize
 * @mm: the mm_struct of the target address space
 *
 * Called to initialize an (on-stack) mmu_gather structure for page-table
 * tear-down from @mm.
 */
void tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm)
{
    __tlb_gather_mmu(tlb, mm, false);
}

static inline void tlb_table_flush(struct mmu_gather *tlb) { }
static inline void tlb_table_init(struct mmu_gather *tlb) { }

static void tlb_batch_pages_flush(struct mmu_gather *tlb)
{
    struct mmu_gather_batch *batch;

    for (batch = &tlb->local; batch && batch->nr; batch = batch->next) {
        free_pages_and_swap_cache(batch->pages, batch->nr);
        batch->nr = 0;
    }
    tlb->active = &tlb->local;
}

static void tlb_flush_mmu_free(struct mmu_gather *tlb)
{
    tlb_table_flush(tlb);
    tlb_batch_pages_flush(tlb);
}

void tlb_flush_mmu(struct mmu_gather *tlb)
{
    tlb_flush_mmu_tlbonly(tlb);
    tlb_flush_mmu_free(tlb);
}

static void tlb_batch_list_free(struct mmu_gather *tlb)
{
    struct mmu_gather_batch *batch, *next;

    for (batch = tlb->local.next; batch; batch = next) {
        next = batch->next;
        free_pages((unsigned long)batch, 0);
    }
    tlb->local.next = NULL;
}

/**
 * tlb_finish_mmu - finish an mmu_gather structure
 * @tlb: the mmu_gather structure to finish
 *
 * Called at the end of the shootdown operation to free up any resources that
 * were required.
 */
void tlb_finish_mmu(struct mmu_gather *tlb)
{
    /*
     * If there are parallel threads are doing PTE changes on same range
     * under non-exclusive lock (e.g., mmap_lock read-side) but defer TLB
     * flush by batching, one thread may end up seeing inconsistent PTEs
     * and result in having stale TLB entries.  So flush TLB forcefully
     * if we detect parallel PTE batching threads.
     *
     * However, some syscalls, e.g. munmap(), may free page tables, this
     * needs force flush everything in the given range. Otherwise this
     * may result in having stale TLB entries for some architectures,
     * e.g. aarch64, that could specify flush what level TLB.
     */
    if (mm_tlb_flush_nested(tlb->mm)) {
#if 0
        /*
         * The aarch64 yields better performance with fullmm by
         * avoiding multiple CPUs spamming TLBI messages at the
         * same time.
         *
         * On x86 non-fullmm doesn't yield significant difference
         * against fullmm.
         */
        tlb->fullmm = 1;
        __tlb_reset_range(tlb);
        tlb->freed_tables = 1;
#endif
        panic("%s: mm_tlb_flush_nested!\n", __func__);
    }

    tlb_flush_mmu(tlb);

    tlb_batch_list_free(tlb);
    dec_tlb_flush_pending(tlb->mm);
}
