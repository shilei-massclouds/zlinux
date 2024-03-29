/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_REF_H
#define _LINUX_PAGE_REF_H

#include <linux/atomic.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>

static inline int page_ref_count(const struct page *page)
{
    return atomic_read(&page->_refcount);
}

/**
 * folio_ref_count - The reference count on this folio.
 * @folio: The folio.
 *
 * The refcount is usually incremented by calls to folio_get() and
 * decremented by calls to folio_put().  Some typical users of the
 * folio refcount:
 *
 * - Each reference from a page table
 * - The page cache
 * - Filesystem private data
 * - The LRU list
 * - Pipes
 * - Direct IO which references this page in the process address space
 *
 * Return: The number of references to this folio.
 */
static inline int folio_ref_count(const struct folio *folio)
{
    return page_ref_count(&folio->page);
}

static inline int page_count(const struct page *page)
{
    return folio_ref_count(page_folio(page));
}

static inline void set_page_count(struct page *page, int v)
{
    atomic_set(&page->_refcount, v);
}

/*
 * Setup the page count before being freed into the page allocator for
 * the first time (boot or memory hotplug)
 */
static inline void init_page_count(struct page *page)
{
    set_page_count(page, 1);
}

static inline int page_ref_dec_and_test(struct page *page)
{
    return atomic_dec_and_test(&page->_refcount);
}

static inline bool page_ref_add_unless(struct page *page, int nr, int u)
{
    bool ret = atomic_add_unless(&page->_refcount, nr, u);

    return ret;
}

static inline bool folio_ref_add_unless(struct folio *folio, int nr, int u)
{
    return page_ref_add_unless(&folio->page, nr, u);
}

static inline bool folio_ref_try_add_rcu(struct folio *folio, int count)
{
    if (unlikely(!folio_ref_add_unless(folio, count, 0))) {
        /* Either the folio has been freed, or will be freed. */
        return false;
    }

    return true;
}

/**
 * folio_try_get_rcu - Attempt to increase the refcount on a folio.
 * @folio: The folio.
 *
 * This is a version of folio_try_get() optimised for non-SMP kernels.
 * If you are still holding the rcu_read_lock() after looking up the
 * page and know that the page cannot have its refcount decreased to
 * zero in interrupt context, you can use this instead of folio_try_get().
 *
 * Example users include get_user_pages_fast() (as pages are not unmapped
 * from interrupt context) and the page cache lookups (as pages are not
 * truncated from interrupt context).  We also know that pages are not
 * frozen in interrupt context for the purposes of splitting or migration.
 *
 * You can also use this function if you're holding a lock that prevents
 * pages being frozen & removed; eg the i_pages lock for the page cache
 * or the mmap_sem or page table lock for page tables.  In this case,
 * it will always succeed, and you could have used a plain folio_get(),
 * but it's sometimes more convenient to have a common function called
 * from both locked and RCU-protected contexts.
 *
 * Return: True if the reference count was successfully incremented.
 */
static inline bool folio_try_get_rcu(struct folio *folio)
{
    return folio_ref_try_add_rcu(folio, 1);
}

static inline void page_ref_inc(struct page *page)
{
    atomic_inc(&page->_refcount);
}

static inline void folio_ref_inc(struct folio *folio)
{
    page_ref_inc(&folio->page);
}

static inline void page_ref_add(struct page *page, int nr)
{
    atomic_add(nr, &page->_refcount);
}

static inline void folio_ref_add(struct folio *folio, int nr)
{
    page_ref_add(&folio->page, nr);
}

static inline int page_ref_sub_and_test(struct page *page, int nr)
{
    return atomic_sub_and_test(nr, &page->_refcount);
}

static inline int folio_ref_sub_and_test(struct folio *folio, int nr)
{
    return page_ref_sub_and_test(&folio->page, nr);
}

static inline int page_ref_freeze(struct page *page, int count)
{
    int ret = likely(atomic_cmpxchg(&page->_refcount, count, 0) == count);

    return ret;
}

static inline int folio_ref_freeze(struct folio *folio, int count)
{
    return page_ref_freeze(&folio->page, count);
}

static inline void page_ref_unfreeze(struct page *page, int count)
{
    VM_BUG_ON_PAGE(page_count(page) != 0, page);
    VM_BUG_ON(count == 0);

    atomic_set_release(&page->_refcount, count);
}

static inline void folio_ref_unfreeze(struct folio *folio, int count)
{
    page_ref_unfreeze(&folio->page, count);
}

#endif /* _LINUX_PAGE_REF_H */
