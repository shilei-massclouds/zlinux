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
//#include <linux/mm_inline.h>
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
#include <linux/page_idle.h>
#endif
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
    panic("%s: END!\n", __func__);
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
    panic("%s: END!\n", __func__);
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
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(folio_mark_accessed);
