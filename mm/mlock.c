// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/mm/mlock.c
 *
 *  (C) Copyright 1995 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 */

//#include <linux/capability.h>
#include <linux/mman.h>
#include <linux/mm.h>
//#include <linux/sched/user.h>
#include <linux/swap.h>
//#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#if 0
#include <linux/pagewalk.h>
#include <linux/mempolicy.h>
#include <linux/syscalls.h>
#endif
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/rmap.h>
#include <linux/mmzone.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
//#include <linux/secretmem.h>

#include "internal.h"

struct mlock_pvec {
    local_lock_t lock;
    struct pagevec vec;
};

static DEFINE_PER_CPU(struct mlock_pvec, mlock_pvec) = {
    .lock = INIT_LOCAL_LOCK(lock),
};

/**
 * mlock_new_page - mlock a newly allocated page not yet on LRU
 * @page: page to be mlocked, either a normal page or a THP head.
 */
void mlock_new_page(struct page *page)
{
#if 0
    struct pagevec *pvec;
    int nr_pages = thp_nr_pages(page);

    local_lock(&mlock_pvec.lock);
    pvec = this_cpu_ptr(&mlock_pvec.vec);
    SetPageMlocked(page);
    mod_zone_page_state(page_zone(page), NR_MLOCK, nr_pages);
    __count_vm_events(UNEVICTABLE_PGMLOCKED, nr_pages);

    get_page(page);
    if (!pagevec_add(pvec, mlock_new(page)) ||
        PageHead(page) || lru_cache_disabled())
        mlock_pagevec(pvec);
    local_unlock(&mlock_pvec.lock);
#endif
    panic("%s: END!\n", __func__);
}

bool can_do_mlock(void)
{
    return true;
}
EXPORT_SYMBOL(can_do_mlock);

/**
 * mlock_folio - mlock a folio already on (or temporarily off) LRU
 * @folio: folio to be mlocked.
 */
void mlock_folio(struct folio *folio)
{
    struct pagevec *pvec;

    local_lock(&mlock_pvec.lock);
    pvec = this_cpu_ptr(&mlock_pvec.vec);

    panic("%s: END!\n", __func__);
}

/*
 * mlock_pagevec() is derived from pagevec_lru_move_fn():
 * perhaps that can make use of such page pointer flags in future,
 * but for now just keep it for mlock.  We could use three separate
 * pagevecs instead, but one feels better (munlocking a full pagevec
 * does not need to drain mlocking pagevecs first).
 */
static void mlock_pagevec(struct pagevec *pvec)
{
    panic("%s: END!\n", __func__);
}

/**
 * munlock_page - munlock a page
 * @page: page to be munlocked, either a normal page or a THP head.
 */
void munlock_page(struct page *page)
{
    struct pagevec *pvec;

    local_lock(&mlock_pvec.lock);
    pvec = this_cpu_ptr(&mlock_pvec.vec);
    /*
     * TestClearPageMlocked(page) must be left to __munlock_page(),
     * which will check whether the page is multiply mlocked.
     */

    get_page(page);
    if (!pagevec_add(pvec, page) || PageHead(page) || lru_cache_disabled())
        mlock_pagevec(pvec);
    local_unlock(&mlock_pvec.lock);
}
