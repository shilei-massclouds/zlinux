// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/spinlock.h>

#include <linux/mm.h>
#include <linux/memremap.h>
#include <linux/pagemap.h>
//#include <linux/rmap.h>
#include <linux/swap.h>
#if 0
#include <linux/swapops.h>
#include <linux/secretmem.h>
#endif

#include <linux/sched/signal.h>
#include <linux/rwsem.h>
#include <linux/hugetlb.h>
#include <linux/migrate.h>
#include <linux/mm_inline.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>

#include <asm/mmu_context.h>
#include <asm/tlbflush.h>

#include "internal.h"

struct follow_page_context {
    struct dev_pagemap *pgmap;
    unsigned int page_mask;
};

static bool is_valid_gup_flags(unsigned int gup_flags)
{
    /*
     * FOLL_PIN must only be set internally by the pin_user_pages*() APIs,
     * never directly by the caller, so enforce that with an assertion:
     */
    if (WARN_ON_ONCE(gup_flags & FOLL_PIN))
        return false;
    /*
     * FOLL_PIN is a prerequisite to FOLL_LONGTERM. Another way of saying
     * that is, FOLL_LONGTERM is a specific case, more restrictive case of
     * FOLL_PIN.
     */
    if (WARN_ON_ONCE(gup_flags & FOLL_LONGTERM))
        return false;

    return true;
}

/*
 * __gup_longterm_locked() is a wrapper for __get_user_pages_locked which
 * allows us to process the FOLL_LONGTERM flag.
 */
static long __gup_longterm_locked(struct mm_struct *mm,
                                  unsigned long start,
                                  unsigned long nr_pages,
                                  struct page **pages,
                                  struct vm_area_struct **vmas,
                                  unsigned int gup_flags)
{
    panic("%s: END!\n", __func__);
}

/*
 * Set the MMF_HAS_PINNED if not set yet; after set it'll be there for the mm's
 * lifecycle.  Avoid setting the bit unless necessary, or it might cause write
 * cache bouncing on large SMP machines for concurrent pinned gups.
 */
static inline void mm_set_has_pinned_flag(unsigned long *mm_flags)
{
    if (!test_bit(MMF_HAS_PINNED, mm_flags))
        set_bit(MMF_HAS_PINNED, mm_flags);
}

/**
 * __get_user_pages() - pin user pages in memory
 * @mm:     mm_struct of target mm
 * @start:  starting user address
 * @nr_pages:   number of pages from start to pin
 * @gup_flags:  flags modifying pin behaviour
 * @pages:  array that receives pointers to the pages pinned.
 *      Should be at least nr_pages long. Or NULL, if caller
 *      only intends to ensure the pages are faulted in.
 * @vmas:   array of pointers to vmas corresponding to each page.
 *      Or NULL if the caller does not require them.
 * @locked:     whether we're still with the mmap_lock held
 *
 * Returns either number of pages pinned (which may be less than the
 * number requested), or an error. Details about the return value:
 *
 * -- If nr_pages is 0, returns 0.
 * -- If nr_pages is >0, but no pages were pinned, returns -errno.
 * -- If nr_pages is >0, and some pages were pinned, returns the number of
 *    pages pinned. Again, this may be less than nr_pages.
 * -- 0 return value is possible when the fault would need to be retried.
 *
 * The caller is responsible for releasing returned @pages, via put_page().
 *
 * @vmas are valid only as long as mmap_lock is held.
 *
 * Must be called with mmap_lock held.  It may be released.  See below.
 *
 * __get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * This does not guarantee that the page exists in the user mappings when
 * __get_user_pages returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If @gup_flags & FOLL_WRITE == 0, the page must not be written to. If
 * the page is written to, set_page_dirty (or set_page_dirty_lock, as
 * appropriate) must be called after the page is finished with, and
 * before put_page is called.
 *
 * If @locked != NULL, *@locked will be set to 0 when mmap_lock is
 * released by an up_read().  That can happen if @gup_flags does not
 * have FOLL_NOWAIT.
 *
 * A caller using such a combination of @locked and @gup_flags
 * must therefore hold the mmap_lock for reading only, and recognize
 * when it's been released.  Otherwise, it must be held for either
 * reading or writing and will not be released.
 *
 * In most cases, get_user_pages or get_user_pages_fast should be used
 * instead of __get_user_pages. __get_user_pages should be used only if
 * you need some special @gup_flags.
 */
static long __get_user_pages(struct mm_struct *mm,
                             unsigned long start, unsigned long nr_pages,
                             unsigned int gup_flags, struct page **pages,
                             struct vm_area_struct **vmas, int *locked)
{
    long ret = 0, i = 0;
    struct vm_area_struct *vma = NULL;
    struct follow_page_context ctx = { NULL };

    if (!nr_pages)
        return 0;

    start = untagged_addr(start);

    VM_BUG_ON(!!pages != !!(gup_flags & (FOLL_GET | FOLL_PIN)));

    /*
     * If FOLL_FORCE is set then do not force a full fault as the hinting
     * fault information is unrelated to the reference behaviour of a task
     * using the address space
     */
    if (!(gup_flags & FOLL_FORCE))
        gup_flags |= FOLL_NUMA;

    do {
        struct page *page;
        unsigned int foll_flags = gup_flags;
        unsigned int page_increm;

        /* first iteration or cross vma bound */
        if (!vma || start >= vma->vm_end) {
            vma = find_extend_vma(mm, start);

            panic("%s: 1!\n", __func__);
        }
        panic("%s: 2!\n", __func__);
    } while (nr_pages);

 out:
    if (ctx.pgmap)
        put_dev_pagemap(ctx.pgmap);
    panic("%s: END!\n", __func__);
    return i ? i : ret;
}

/*
 * Please note that this function, unlike __get_user_pages will not
 * return 0 for nr_pages > 0 without FOLL_NOWAIT
 */
static __always_inline long
__get_user_pages_locked(struct mm_struct *mm,
                        unsigned long start,
                        unsigned long nr_pages,
                        struct page **pages,
                        struct vm_area_struct **vmas,
                        int *locked,
                        unsigned int flags)
{
    long ret, pages_done;
    bool lock_dropped;

    if (locked) {
        /* if VM_FAULT_RETRY can be returned, vmas become invalid */
        BUG_ON(vmas);
        /* check caller initialized locked */
        BUG_ON(*locked != 1);
    }

    if (flags & FOLL_PIN)
        mm_set_has_pinned_flag(&mm->flags);

    /*
     * FOLL_PIN and FOLL_GET are mutually exclusive. Traditional behavior
     * is to set FOLL_GET if the caller wants pages[] filled in (but has
     * carelessly failed to specify FOLL_GET), so keep doing that, but only
     * for FOLL_GET, not for the newer FOLL_PIN.
     *
     * FOLL_PIN always expects pages to be non-null, but no need to assert
     * that here, as any failures will be obvious enough.
     */
    if (pages && !(flags & FOLL_PIN))
        flags |= FOLL_GET;

    pages_done = 0;
    lock_dropped = false;
    for (;;) {
        ret = __get_user_pages(mm, start, nr_pages, flags, pages, vmas, locked);

        panic("%s: 1!\n", __func__);
    }
    panic("%s: END!\n", __func__);
}

static long __get_user_pages_remote(struct mm_struct *mm,
                                    unsigned long start, unsigned long nr_pages,
                                    unsigned int gup_flags, struct page **pages,
                                    struct vm_area_struct **vmas, int *locked)
{
    /*
     * Parts of FOLL_LONGTERM behavior are incompatible with
     * FAULT_FLAG_ALLOW_RETRY because of the FS DAX check requirement on
     * vmas. However, this only comes up if locked is set, and there are
     * callers that do request FOLL_LONGTERM, but do not set locked. So,
     * allow what we can.
     */
    if (gup_flags & FOLL_LONGTERM) {
        if (WARN_ON_ONCE(locked))
            return -EINVAL;
        /*
         * This will check the vmas (even if our vmas arg is NULL)
         * and return -ENOTSUPP if DAX isn't allowed in this case:
         */
        return __gup_longterm_locked(mm, start, nr_pages, pages, vmas,
                                     gup_flags | FOLL_TOUCH | FOLL_REMOTE);
    }

    return __get_user_pages_locked(mm, start, nr_pages, pages, vmas, locked,
                                   gup_flags | FOLL_TOUCH | FOLL_REMOTE);
}

/**
 * get_user_pages_remote() - pin user pages in memory
 * @mm:     mm_struct of target mm
 * @start:  starting user address
 * @nr_pages:   number of pages from start to pin
 * @gup_flags:  flags modifying lookup behaviour
 * @pages:  array that receives pointers to the pages pinned.
 *      Should be at least nr_pages long. Or NULL, if caller
 *      only intends to ensure the pages are faulted in.
 * @vmas:   array of pointers to vmas corresponding to each page.
 *      Or NULL if the caller does not require them.
 * @locked: pointer to lock flag indicating whether lock is held and
 *      subsequently whether VM_FAULT_RETRY functionality can be
 *      utilised. Lock must initially be held.
 *
 * Returns either number of pages pinned (which may be less than the
 * number requested), or an error. Details about the return value:
 *
 * -- If nr_pages is 0, returns 0.
 * -- If nr_pages is >0, but no pages were pinned, returns -errno.
 * -- If nr_pages is >0, and some pages were pinned, returns the number of
 *    pages pinned. Again, this may be less than nr_pages.
 *
 * The caller is responsible for releasing returned @pages, via put_page().
 *
 * @vmas are valid only as long as mmap_lock is held.
 *
 * Must be called with mmap_lock held for read or write.
 *
 * get_user_pages_remote walks a process's page tables and takes a reference
 * to each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 *
 * This does not guarantee that the page exists in the user mappings when
 * get_user_pages_remote returns, and there may even be a completely different
 * page there in some cases (eg. if mmapped pagecache has been invalidated
 * and subsequently re faulted). However it does guarantee that the page
 * won't be freed completely. And mostly callers simply care that the page
 * contains data that was valid *at some point in time*. Typically, an IO
 * or similar operation cannot guarantee anything stronger anyway because
 * locks can't be held over the syscall boundary.
 *
 * If gup_flags & FOLL_WRITE == 0, the page must not be written to. If the page
 * is written to, set_page_dirty (or set_page_dirty_lock, as appropriate) must
 * be called after the page is finished with, and before put_page is called.
 *
 * get_user_pages_remote is typically used for fewer-copy IO operations,
 * to get a handle on the memory by some means other than accesses
 * via the user virtual addresses. The pages may be submitted for
 * DMA to devices or accessed via their kernel linear mapping (via the
 * kmap APIs). Care should be taken to use the correct cache flushing APIs.
 *
 * See also get_user_pages_fast, for performance critical applications.
 *
 * get_user_pages_remote should be phased out in favor of
 * get_user_pages_locked|unlocked or get_user_pages_fast. Nothing
 * should use get_user_pages_remote because it cannot pass
 * FAULT_FLAG_ALLOW_RETRY to handle_mm_fault.
 */
long get_user_pages_remote(struct mm_struct *mm,
                           unsigned long start, unsigned long nr_pages,
                           unsigned int gup_flags, struct page **pages,
                           struct vm_area_struct **vmas, int *locked)
{
    if (!is_valid_gup_flags(gup_flags))
        return -EINVAL;

    return __get_user_pages_remote(mm, start, nr_pages, gup_flags,
                                   pages, vmas, locked);
}
EXPORT_SYMBOL(get_user_pages_remote);

/**
 * populate_vma_page_range() -  populate a range of pages in the vma.
 * @vma:   target vma
 * @start: start address
 * @end:   end address
 * @locked: whether the mmap_lock is still held
 *
 * This takes care of mlocking the pages too if VM_LOCKED is set.
 *
 * Return either number of pages pinned in the vma, or a negative error
 * code on error.
 *
 * vma->vm_mm->mmap_lock must be held.
 *
 * If @locked is NULL, it may be held for read or write and will
 * be unperturbed.
 *
 * If @locked is non-NULL, it must held for read only and may be
 * released.  If it's released, *@locked will be set to 0.
 */
long populate_vma_page_range(struct vm_area_struct *vma,
                             unsigned long start, unsigned long end,
                             int *locked)
{
    panic("%s: END!\n", __func__);
}
