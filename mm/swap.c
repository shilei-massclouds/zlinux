// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the operation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * Documentation/admin-guide/sysctl/vm.rst.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
//#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/mm_inline.h>
#include <linux/percpu_counter.h>
//#include <linux/memremap.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
//#include <linux/notifier.h>
#include <linux/backing-dev.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#if 0
#include <linux/uio.h>
#include <linux/hugetlb.h>
#endif
#include <linux/page_idle.h>
#include <linux/buffer_head.h>
#include <linux/local_lock.h>

#include "internal.h"

/*
 * The following struct pagevec are grouped together because they are protected
 * by disabling preemption (and interrupts remain enabled).
 */
struct lru_pvecs {
    local_lock_t lock;
    struct pagevec lru_add;
    struct pagevec lru_deactivate_file;
    struct pagevec lru_deactivate;
    struct pagevec lru_lazyfree;
    struct pagevec activate_page;
};
static DEFINE_PER_CPU(struct lru_pvecs, lru_pvecs) = {
    .lock = INIT_LOCAL_LOCK(lock),
};

atomic_t lru_disable_count = ATOMIC_INIT(0);

static void __put_single_page(struct page *page)
{
#if 0
    __page_cache_release(page);
    free_unref_page(page, 0);
#endif
    pr_warn("%s: END!\n", __func__);
}

static void __put_compound_page(struct page *page)
{
    /*
     * __page_cache_release() is supposed to be called for thp, not for
     * hugetlb. This is because hugetlb page does never have PageLRU set
     * (it's never listed to any LRU lists) and no memcg routines should
     * be called for hugetlb (it has a separate hugetlb_cgroup.)
     */
#if 0
    if (!PageHuge(page))
        __page_cache_release(page);
    destroy_compound_page(page);
#endif
    pr_warn("%s: END!\n", __func__);
}

void __put_page(struct page *page)
{
    if (unlikely(PageCompound(page)))
        __put_compound_page(page);
    else
        __put_single_page(page);
}
EXPORT_SYMBOL(__put_page);

static void __pagevec_lru_add_fn(struct folio *folio, struct lruvec *lruvec)
{
    int was_unevictable = folio_test_clear_unevictable(folio);
    long nr_pages = folio_nr_pages(folio);

    VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);

    folio_set_lru(folio);
    /*
     * Is an smp_mb__after_atomic() still required here, before
     * folio_evictable() tests PageMlocked, to rule out the possibility
     * of stranding an evictable folio on an unevictable LRU?  I think
     * not, because __munlock_page() only clears PageMlocked while the LRU
     * lock is held.
     *
     * (That is not true of __page_cache_release(), and not necessarily
     * true of release_pages(): but those only clear PageMlocked after
     * put_page_testzero() has excluded any other users of the page.)
     */
    if (folio_evictable(folio)) {
#if 0
        if (was_unevictable)
            __count_vm_events(UNEVICTABLE_PGRESCUED, nr_pages);
#endif
    } else {
        folio_clear_active(folio);
        folio_set_unevictable(folio);
        /*
         * folio->mlock_count = !!folio_test_mlocked(folio)?
         * But that leaves __mlock_page() in doubt whether another
         * actor has already counted the mlock or not.  Err on the
         * safe side, underestimate, let page reclaim fix it, rather
         * than leaving a page on the unevictable LRU indefinitely.
         */
        folio->mlock_count = 0;
#if 0
        if (!was_unevictable)
            __count_vm_events(UNEVICTABLE_PGCULLED, nr_pages);
#endif
    }

    lruvec_add_folio(lruvec, folio);
}

/**
 * release_pages - batched put_page()
 * @pages: array of pages to release
 * @nr: number of pages
 *
 * Decrement the reference count on all the pages in @pages.  If it
 * fell to zero, remove the page from the LRU and free it.
 */
void release_pages(struct page **pages, int nr)
{
    int i;
    LIST_HEAD(pages_to_free);
    struct lruvec *lruvec = NULL;
    unsigned long flags = 0;
    unsigned int lock_batch;

    for (i = 0; i < nr; i++) {
        struct page *page = pages[i];
        struct folio *folio = page_folio(page);

        /*
         * Make sure the IRQ-safe lock-holding time does not get
         * excessive with a continuous string of pages from the
         * same lruvec. The lock is held only if lruvec != NULL.
         */
        if (lruvec && ++lock_batch == SWAP_CLUSTER_MAX) {
            unlock_page_lruvec_irqrestore(lruvec, flags);
            lruvec = NULL;
        }

        page = &folio->page;

        if (!put_page_testzero(page))
            continue;

        if (PageCompound(page)) {
            if (lruvec) {
                unlock_page_lruvec_irqrestore(lruvec, flags);
                lruvec = NULL;
            }
            __put_compound_page(page);
            continue;
        }

        if (PageLRU(page)) {
            struct lruvec *prev_lruvec = lruvec;

            lruvec = folio_lruvec_relock_irqsave(folio, lruvec, &flags);
            if (prev_lruvec != lruvec)
                lock_batch = 0;

            del_page_from_lru_list(page, lruvec);
            __clear_page_lru_flags(page);
        }

        /*
         * In rare cases, when truncation or holepunching raced with
         * munlock after VM_LOCKED was cleared, Mlocked may still be
         * found set here.  This does not indicate a problem, unless
         * "unevictable_pgs_cleared" appears worryingly large.
         */
        if (unlikely(PageMlocked(page))) {
#if 0
            __ClearPageMlocked(page);
            dec_zone_page_state(page, NR_MLOCK);
            count_vm_event(UNEVICTABLE_PGCLEARED);
#endif
            panic("%s: PageMlocked!\n", __func__);
        }

        list_add(&page->lru, &pages_to_free);
    }
    if (lruvec)
        unlock_page_lruvec_irqrestore(lruvec, flags);

    free_unref_page_list(&pages_to_free);
}

/*
 * Add the passed pages to the LRU, then drop the caller's refcount
 * on them.  Reinitialises the caller's pagevec.
 */
void __pagevec_lru_add(struct pagevec *pvec)
{
    int i;
    struct lruvec *lruvec = NULL;
    unsigned long flags = 0;

    for (i = 0; i < pagevec_count(pvec); i++) {
        struct folio *folio = page_folio(pvec->pages[i]);

        lruvec = folio_lruvec_relock_irqsave(folio, lruvec, &flags);
        __pagevec_lru_add_fn(folio, lruvec);
    }
    if (lruvec)
        unlock_page_lruvec_irqrestore(lruvec, flags);
    release_pages(pvec->pages, pvec->nr);
    pagevec_reinit(pvec);
}

/* return true if pagevec needs to drain */
static bool pagevec_add_and_need_flush(struct pagevec *pvec, struct page *page)
{
    bool ret = false;

    if (!pagevec_add(pvec, page) || PageCompound(page) || lru_cache_disabled())
        ret = true;

    return ret;
}

/**
 * folio_add_lru - Add a folio to an LRU list.
 * @folio: The folio to be added to the LRU.
 *
 * Queue the folio for addition to the LRU. The decision on whether
 * to add the page to the [in]active [file|anon] list is deferred until the
 * pagevec is drained. This gives a chance for the caller of folio_add_lru()
 * have the folio added to the active list using folio_mark_accessed().
 */
void folio_add_lru(struct folio *folio)
{
    struct pagevec *pvec;

    VM_BUG_ON_FOLIO(folio_test_active(folio) &&
                    folio_test_unevictable(folio), folio);
    VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);

    folio_get(folio);
    local_lock(&lru_pvecs.lock);
    pvec = this_cpu_ptr(&lru_pvecs.lru_add);
    if (pagevec_add_and_need_flush(pvec, &folio->page))
        __pagevec_lru_add(pvec);
    local_unlock(&lru_pvecs.lock);
}
EXPORT_SYMBOL(folio_add_lru);

static void folio_activate(struct folio *folio)
{
#if 0
    if (folio_test_lru(folio) && !folio_test_active(folio) &&
        !folio_test_unevictable(folio)) {
        struct pagevec *pvec;

        folio_get(folio);
        local_lock(&lru_pvecs.lock);
        pvec = this_cpu_ptr(&lru_pvecs.activate_page);
        if (pagevec_add_and_need_flush(pvec, &folio->page))
            pagevec_lru_move_fn(pvec, __activate_page);
        local_unlock(&lru_pvecs.lock);
    }
#endif
    panic("%s: END!\n", __func__);
}

static void __lru_cache_activate_folio(struct folio *folio)
{
    struct pagevec *pvec;
    int i;

    local_lock(&lru_pvecs.lock);
    pvec = this_cpu_ptr(&lru_pvecs.lru_add);

    /*
     * Search backwards on the optimistic assumption that the page being
     * activated has just been added to this pagevec. Note that only
     * the local pagevec is examined as a !PageLRU page could be in the
     * process of being released, reclaimed, migrated or on a remote
     * pagevec that is currently being drained. Furthermore, marking
     * a remote pagevec's page PageActive potentially hits a race where
     * a page is marked PageActive just after it is added to the inactive
     * list causing accounting errors and BUG_ON checks to trigger.
     */
    for (i = pagevec_count(pvec) - 1; i >= 0; i--) {
        struct page *pagevec_page = pvec->pages[i];

        if (pagevec_page == &folio->page) {
            folio_set_active(folio);
            break;
        }
    }

    local_unlock(&lru_pvecs.lock);
}

/*
 * Mark a page as having seen activity.
 *
 * inactive,unreferenced    ->  inactive,referenced
 * inactive,referenced      ->  active,unreferenced
 * active,unreferenced      ->  active,referenced
 *
 * When a newly allocated page is not yet visible, so safe for non-atomic ops,
 * __SetPageReferenced(page) may be substituted for mark_page_accessed(page).
 */
void folio_mark_accessed(struct folio *folio)
{
    if (!folio_test_referenced(folio)) {
        folio_set_referenced(folio);
    } else if (folio_test_unevictable(folio)) {
        /*
         * Unevictable pages are on the "LRU_UNEVICTABLE" list. But,
         * this list is never rotated or maintained, so marking an
         * unevictable page accessed has no effect.
         */
    } else if (!folio_test_active(folio)) {
        /*
         * If the page is on the LRU, queue it for activation via
         * lru_pvecs.activate_page. Otherwise, assume the page is on a
         * pagevec, mark it active and it'll be moved to the active
         * LRU on the next drain.
         */
        if (folio_test_lru(folio))
            folio_activate(folio);
        else
            __lru_cache_activate_folio(folio);
        folio_clear_referenced(folio);
        //workingset_activation(folio);
    }
    if (folio_test_idle(folio))
        folio_clear_idle(folio);
}
EXPORT_SYMBOL(folio_mark_accessed);

unsigned pagevec_lookup_range_tag(struct pagevec *pvec,
                                  struct address_space *mapping,
                                  pgoff_t *index,
                                  pgoff_t end,
                                  xa_mark_t tag)
{
    pvec->nr = find_get_pages_range_tag(mapping, index, end, tag,
                                        PAGEVEC_SIZE, pvec->pages);
    return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup_range_tag);

void lru_add_drain(void)
{
#if 0
    local_lock(&lru_pvecs.lock);
    lru_add_drain_cpu(smp_processor_id());
    local_unlock(&lru_pvecs.lock);
    mlock_page_drain_local();
#endif
    pr_warn("%s: NO implementation!\n", __func__);
}

/*
 * The pages which we're about to release may be in the deferred lru-addition
 * queues.  That would prevent them from really being freed right now.  That's
 * OK from a correctness point of view but is inefficient - those pages may be
 * cache-warm and we want to give them back to the page allocator ASAP.
 *
 * So __pagevec_release() will drain those queues here.  __pagevec_lru_add()
 * and __pagevec_lru_add_active() call release_pages() directly to avoid
 * mutual recursion.
 */
void __pagevec_release(struct pagevec *pvec)
{
    if (!pvec->percpu_pvec_drained) {
        lru_add_drain();
        pvec->percpu_pvec_drained = true;
    }
    release_pages(pvec->pages, pagevec_count(pvec));
    pagevec_reinit(pvec);
}
EXPORT_SYMBOL(__pagevec_release);

/**
 * lru_cache_add_inactive_or_unevictable
 * @page:  the page to be added to LRU
 * @vma:   vma in which page is mapped for determining reclaimability
 *
 * Place @page on the inactive or unevictable LRU list, depending on its
 * evictability.
 */
void lru_cache_add_inactive_or_unevictable(struct page *page,
                                           struct vm_area_struct *vma)
{
    VM_BUG_ON_PAGE(PageLRU(page), page);

    if (unlikely((vma->vm_flags & (VM_LOCKED | VM_SPECIAL)) == VM_LOCKED))
        mlock_new_page(page);
    else
        lru_cache_add(page);
}
