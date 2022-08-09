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

static int
check_vma_flags(struct vm_area_struct *vma, unsigned long gup_flags)
{
    vm_flags_t vm_flags = vma->vm_flags;
    int write = (gup_flags & FOLL_WRITE);
    int foreign = (gup_flags & FOLL_REMOTE);

    if (vm_flags & (VM_IO | VM_PFNMAP))
        return -EFAULT;

    if (gup_flags & FOLL_ANON && !vma_is_anonymous(vma))
        return -EFAULT;

    if ((gup_flags & FOLL_LONGTERM) && vma_is_fsdax(vma))
        return -EOPNOTSUPP;

#if 0
    if (vma_is_secretmem(vma))
        return -EFAULT;
#endif

    if (write) {
        if (!(vm_flags & VM_WRITE)) {
            if (!(gup_flags & FOLL_FORCE))
                return -EFAULT;
            /*
             * We used to let the write,force case do COW in a
             * VM_MAYWRITE VM_SHARED !VM_WRITE vma, so ptrace could
             * set a breakpoint in a read-only mapping of an
             * executable, without corrupting the file (yet only
             * when that file had been opened for writing!).
             * Anon pages in shared mappings are surprising: now
             * just reject it.
             */
            if (!is_cow_mapping(vm_flags))
                return -EFAULT;
        }
    } else if (!(vm_flags & VM_READ)) {
        if (!(gup_flags & FOLL_FORCE))
            return -EFAULT;
        /*
         * Is there actually any vma we can reach here which does not
         * have VM_MAYREAD set?
         */
        if (!(vm_flags & VM_MAYREAD))
            return -EFAULT;
    }

    return 0;
}

static struct page *no_page_table(struct vm_area_struct *vma,
                                  unsigned int flags)
{
    /*
     * When core dumping an enormous anonymous area that nobody
     * has touched so far, we don't want to allocate unnecessary pages or
     * page tables.  Return error instead of NULL to skip handle_mm_fault,
     * then get_dump_page() will return NULL to leave a hole in the dump.
     * But we can only make this optimization where a hole would surely
     * be zero-filled if handle_mm_fault() actually did handle it.
     */
    if ((flags & FOLL_DUMP) &&
        (vma_is_anonymous(vma) || !vma->vm_ops->fault))
        return ERR_PTR(-EFAULT);
    return NULL;
}

/*
 * FOLL_FORCE can write to even unwritable pte's, but only
 * after we've gone through a COW cycle and they are dirty.
 */
static inline bool can_follow_write_pte(pte_t pte, unsigned int flags)
{
    return pte_write(pte) ||
        ((flags & FOLL_FORCE) && (flags & FOLL_COW) && pte_dirty(pte));
}

static int follow_pfn_pte(struct vm_area_struct *vma,
                          unsigned long address,
                          pte_t *pte, unsigned int flags)
{
    if (flags & FOLL_TOUCH) {
        pte_t entry = *pte;

        if (flags & FOLL_WRITE)
            entry = pte_mkdirty(entry);
        entry = pte_mkyoung(entry);

        if (!pte_same(*pte, entry)) {
            set_pte_at(vma->vm_mm, address, pte, entry);
            update_mmu_cache(vma, address, pte);
        }
    }

    /* Proper page table entry exists, but no corresponding struct page */
    return -EEXIST;
}

/**
 * try_grab_page() - elevate a page's refcount by a flag-dependent amount
 * @page:    pointer to page to be grabbed
 * @flags:   gup flags: these are the FOLL_* flag values.
 *
 * This might not do anything at all, depending on the flags argument.
 *
 * "grab" names in this file mean, "look at flags to decide whether to use
 * FOLL_PIN or FOLL_GET behavior, when incrementing the page's refcount.
 *
 * Either FOLL_PIN or FOLL_GET (or neither) may be set, but not both at the same
 * time. Cases: please see the try_grab_folio() documentation, with
 * "refs=1".
 *
 * Return: true for success, or if no action was required (if neither FOLL_PIN
 * nor FOLL_GET was set, nothing is done). False for failure: FOLL_GET or
 * FOLL_PIN was set, but the page could not be grabbed.
 */
bool __must_check try_grab_page(struct page *page, unsigned int flags)
{
    struct folio *folio = page_folio(page);

    WARN_ON_ONCE((flags & (FOLL_GET | FOLL_PIN)) ==
                 (FOLL_GET | FOLL_PIN));
    if (WARN_ON_ONCE(folio_ref_count(folio) <= 0))
        return false;

    if (flags & FOLL_GET)
        folio_ref_inc(folio);
    else if (flags & FOLL_PIN) {
        /*
         * Similar to try_grab_folio(): be sure to *also*
         * increment the normal page refcount field at least once,
         * so that the page really is pinned.
         */
        if (folio_test_large(folio)) {
            folio_ref_add(folio, 1);
            atomic_add(1, folio_pincount_ptr(folio));
        } else {
            folio_ref_add(folio, GUP_PIN_COUNTING_BIAS);
        }

        //node_stat_mod_folio(folio, NR_FOLL_PIN_ACQUIRED, 1);
    }

    return true;
}

static struct page *follow_page_pte(struct vm_area_struct *vma,
                                    unsigned long address,
                                    pmd_t *pmd,
                                    unsigned int flags,
                                    struct dev_pagemap **pgmap)
{
    struct mm_struct *mm = vma->vm_mm;
    struct page *page;
    spinlock_t *ptl;
    pte_t *ptep, pte;
    int ret;

    /* FOLL_GET and FOLL_PIN are mutually exclusive. */
    if (WARN_ON_ONCE((flags & (FOLL_PIN | FOLL_GET)) == (FOLL_PIN | FOLL_GET)))
        return ERR_PTR(-EINVAL);
retry:
    if (unlikely(pmd_bad(*pmd)))
        return no_page_table(vma, flags);

    ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
    pte = *ptep;
    if (!pte_present(pte)) {
        panic("%s: !pte_present\n", __func__);
    }
    if ((flags & FOLL_NUMA) && pte_protnone(pte))
        goto no_page;
    if ((flags & FOLL_WRITE) && !can_follow_write_pte(pte, flags)) {
        pte_unmap_unlock(ptep, ptl);
        return NULL;
    }

    page = vm_normal_page(vma, address, pte);
    if (unlikely(!page)) {
        if (flags & FOLL_DUMP) {
            /* Avoid special (like zero) pages in core dumps */
            page = ERR_PTR(-EFAULT);
            goto out;
        }

        if (is_zero_pfn(pte_pfn(pte))) {
            page = pte_page(pte);
        } else {
            ret = follow_pfn_pte(vma, address, ptep, flags);
            page = ERR_PTR(ret);
            goto out;
        }
    }

    /* try_grab_page() does nothing unless FOLL_GET or
     * FOLL_PIN is set. */
    if (unlikely(!try_grab_page(page, flags))) {
        page = ERR_PTR(-ENOMEM);
        goto out;
    }
    if (flags & FOLL_TOUCH) {
        if ((flags & FOLL_WRITE) && !pte_dirty(pte) && !PageDirty(page))
            set_page_dirty(page);
        /*
         * pte_mkyoung() would be more correct here, but atomic care
         * is needed to avoid losing the dirty bit: it is easier to use
         * mark_page_accessed().
         */
        mark_page_accessed(page);
    }
 out:
    pte_unmap_unlock(ptep, ptl);
    return page;
 no_page:
    pte_unmap_unlock(ptep, ptl);
    if (!pte_none(pte))
        return NULL;
    return no_page_table(vma, flags);
}

static struct page *
follow_pmd_mask(struct vm_area_struct *vma,
                unsigned long address, pud_t *pudp,
                unsigned int flags,
                struct follow_page_context *ctx)
{
    pmd_t *pmd, pmdval;
    spinlock_t *ptl;
    struct page *page;
    struct mm_struct *mm = vma->vm_mm;

    pmd = pmd_offset(pudp, address);
    /*
     * The READ_ONCE() will stabilize the pmdval in a register or
     * on the stack so that it will stop changing under the code.
     */
    pmdval = READ_ONCE(*pmd);
    if (pmd_none(pmdval))
        return no_page_table(vma, flags);
    if (pmd_huge(pmdval) && is_vm_hugetlb_page(vma)) {
        page = follow_huge_pmd(mm, address, pmd, flags);
        if (page)
            return page;
        return no_page_table(vma, flags);
    }
 retry:
    if (!pmd_present(pmdval)) {
        panic("%s: !pmd_present\n", __func__);
    }

    if (likely(!pmd_trans_huge(pmdval)))
        return follow_page_pte(vma, address, pmd, flags, &ctx->pgmap);

    panic("%s: END!\n", __func__);
}

static struct page *
follow_pud_mask(struct vm_area_struct *vma,
                unsigned long address, p4d_t *p4dp,
                unsigned int flags,
                struct follow_page_context *ctx)
{
    pud_t *pud;
    spinlock_t *ptl;
    struct page *page;
    struct mm_struct *mm = vma->vm_mm;

    pud = pud_offset(p4dp, address);
    if (pud_none(*pud))
        return no_page_table(vma, flags);
    if (pud_huge(*pud) && is_vm_hugetlb_page(vma)) {
        page = follow_huge_pud(mm, address, pud, flags);
        if (page)
            return page;
        return no_page_table(vma, flags);
    }

    if (unlikely(pud_bad(*pud)))
        return no_page_table(vma, flags);

    return follow_pmd_mask(vma, address, pud, flags, ctx);
}

static struct page *
follow_p4d_mask(struct vm_area_struct *vma,
                unsigned long address, pgd_t *pgdp,
                unsigned int flags,
                struct follow_page_context *ctx)
{
    p4d_t *p4d;
    struct page *page;

    p4d = p4d_offset(pgdp, address);
    if (p4d_none(*p4d))
        return no_page_table(vma, flags);
    if (unlikely(p4d_bad(*p4d)))
        return no_page_table(vma, flags);

    return follow_pud_mask(vma, address, p4d, flags, ctx);
}

/**
 * follow_page_mask - look up a page descriptor from a user-virtual address
 * @vma: vm_area_struct mapping @address
 * @address: virtual address to look up
 * @flags: flags modifying lookup behaviour
 * @ctx: contains dev_pagemap for %ZONE_DEVICE memory pinning and a
 *       pointer to output page_mask
 *
 * @flags can have FOLL_ flags set, defined in <linux/mm.h>
 *
 * When getting pages from ZONE_DEVICE memory, the @ctx->pgmap caches
 * the device's dev_pagemap metadata to avoid repeating expensive lookups.
 *
 * On output, the @ctx->page_mask is set according to the size of the page.
 *
 * Return: the mapped (struct page *), %NULL if no mapping exists, or
 * an error pointer if there is a mapping to something not represented
 * by a page descriptor (see also vm_normal_page()).
 */
static struct page *follow_page_mask(struct vm_area_struct *vma,
                                     unsigned long address,
                                     unsigned int flags,
                                     struct follow_page_context *ctx)
{
    pgd_t *pgd;
    struct page *page;
    struct mm_struct *mm = vma->vm_mm;

    ctx->page_mask = 0;

    /* make this handle hugepd */
    page = follow_huge_addr(mm, address, flags & FOLL_WRITE);
    if (!IS_ERR(page)) {
        WARN_ON_ONCE(flags & (FOLL_GET | FOLL_PIN));
        return page;
    }

    pgd = pgd_offset(mm, address);

    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
        return no_page_table(vma, flags);

    return follow_p4d_mask(vma, address, pgd, flags, ctx);
}

/*
 * mmap_lock must be held on entry.  If @locked != NULL and *@flags
 * does not include FOLL_NOWAIT, the mmap_lock may be released.  If it
 * is, *@locked will be set to 0 and -EBUSY returned.
 */
static int faultin_page(struct vm_area_struct *vma,
                        unsigned long address, unsigned int *flags, int *locked)
{
    unsigned int fault_flags = 0;
    vm_fault_t ret;

    if (*flags & FOLL_NOFAULT)
        return -EFAULT;
    if (*flags & FOLL_WRITE)
        fault_flags |= FAULT_FLAG_WRITE;
    if (*flags & FOLL_REMOTE)
        fault_flags |= FAULT_FLAG_REMOTE;
    if (locked)
        fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;
    if (*flags & FOLL_NOWAIT)
        fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
    if (*flags & FOLL_TRIED) {
        /*
         * Note: FAULT_FLAG_ALLOW_RETRY and FAULT_FLAG_TRIED
         * can co-exist
         */
        fault_flags |= FAULT_FLAG_TRIED;
    }

    ret = handle_mm_fault(vma, address, fault_flags, NULL);
    if (ret & VM_FAULT_ERROR) {
        int err = vm_fault_to_errno(ret, *flags);

        if (err)
            return err;
        BUG();
    }

    if (ret & VM_FAULT_RETRY) {
        if (locked && !(fault_flags & FAULT_FLAG_RETRY_NOWAIT))
            *locked = 0;
        return -EBUSY;
    }

    /*
     * The VM_FAULT_WRITE bit tells us that do_wp_page has broken COW when
     * necessary, even if maybe_mkwrite decided not to set pte_write. We
     * can thus safely do subsequent page lookups as if they were reads.
     * But only do so when looping for pte_write is futile: in some cases
     * userspace may also be wanting to write to the gotten user page,
     * which a read fault here might prevent (a readonly page might get
     * reCOWed by userspace write).
     */
    if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
        *flags |= FOLL_COW;
    return 0;
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
            if (!vma) {
                ret = -EFAULT;
                goto out;
            }
            ret = check_vma_flags(vma, gup_flags);
            if (ret)
                goto out;

            if (is_vm_hugetlb_page(vma)) {
                panic("%s: is_vm_hugetlb_page!\n", __func__);
            }
        }

     retry:
#if 0
        /*
         * If we have a pending SIGKILL, don't keep faulting pages and
         * potentially allocating memory.
         */
        if (fatal_signal_pending(current)) {
            ret = -EINTR;
            goto out;
        }
#endif
        cond_resched();

        page = follow_page_mask(vma, start, foll_flags, &ctx);
        if (!page) {
            ret = faultin_page(vma, start, &foll_flags, locked);
            switch (ret) {
            case 0:
                goto retry;
            case -EBUSY:
                ret = 0;
                fallthrough;
            case -EFAULT:
            case -ENOMEM:
            case -EHWPOISON:
                goto out;
            }
            BUG();
        } else if (PTR_ERR(page) == -EEXIST) {
            /*
             * Proper page table entry exists, but no corresponding
             * struct page. If the caller expects **pages to be
             * filled in, bail out now, because that can't be done
             * for this page.
             */
            if (pages) {
                ret = PTR_ERR(page);
                goto out;
            }

            goto next_page;
        } else if (IS_ERR(page)) {
            ret = PTR_ERR(page);
            goto out;
        }
        if (pages) {
            pages[i] = page;
            flush_dcache_page(page);
            ctx.page_mask = 0;
        }
     next_page:
        if (vmas) {
            vmas[i] = vma;
            ctx.page_mask = 0;
        }
        page_increm = 1 + (~(start >> PAGE_SHIFT) & ctx.page_mask);
        if (page_increm > nr_pages)
            page_increm = nr_pages;
        i += page_increm;
        start += page_increm * PAGE_SIZE;
        nr_pages -= page_increm;
    } while (nr_pages);

 out:
    if (ctx.pgmap)
        put_dev_pagemap(ctx.pgmap);
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
        if (!locked)
            /* VM_FAULT_RETRY couldn't trigger, bypass */
            return ret;

        /* VM_FAULT_RETRY cannot return errors */
        if (!*locked) {
            BUG_ON(ret < 0);
            BUG_ON(ret >= nr_pages);
        }

        if (ret > 0) {
            nr_pages -= ret;
            pages_done += ret;
            if (!nr_pages)
                break;
        }
        if (*locked) {
            /*
             * VM_FAULT_RETRY didn't trigger or it was a
             * FOLL_NOWAIT.
             */
            if (!pages_done)
                pages_done = ret;
            break;
        }
        /*
         * VM_FAULT_RETRY triggered, so seek to the faulting offset.
         * For the prefault case (!pages) we only update counts.
         */
        if (likely(pages))
            pages += ret;
        start += ret << PAGE_SHIFT;
        lock_dropped = true;

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
