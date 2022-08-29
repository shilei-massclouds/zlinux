// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/pagevec.h>
#include <linux/migrate.h>
#include <linux/vmalloc.h>
//#include <linux/swap_slots.h>
#include <linux/huge_mm.h>
#include <linux/shmem_fs.h>
#include "internal.h"

struct address_space *swapper_spaces[MAX_SWAPFILES] __read_mostly;
static unsigned int nr_swapper_spaces[MAX_SWAPFILES] __read_mostly;
static bool enable_vma_readahead __read_mostly = true;

/*
 * If we are the only user, then try to free up the swap cache.
 *
 * Its ok to check for PageSwapCache without the page lock
 * here because we are going to recheck again inside
 * try_to_free_swap() _with_ the lock.
 *                  - Marcelo
 */
void free_swap_cache(struct page *page)
{
    if (PageSwapCache(page) && !page_mapped(page) && trylock_page(page)) {
#if 0
        try_to_free_swap(page);
        unlock_page(page);
#endif
        panic("%s: END!\n", __func__);
    }
}

/*
 * Passed an array of pages, drop them all from swapcache and then release
 * them.  They are removed from the LRU and freed if this is their last use.
 */
void free_pages_and_swap_cache(struct page **pages, int nr)
{
    struct page **pagep = pages;
    int i;

    lru_add_drain();
    for (i = 0; i < nr; i++)
        free_swap_cache(pagep[i]);
    release_pages(pagep, nr);
}
