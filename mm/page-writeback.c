// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/page-writeback.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 * Copyright (C) 2007 Red Hat, Inc., Peter Zijlstra
 *
 * Contains functions related to writing back dirty pages at the
 * address_space level.
 *
 * 10Apr2002    Andrew Morton
 *      Initial version
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
//#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/init.h>
/*
#include <linux/backing-dev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/blkdev.h>
#include <linux/mpage.h>
#include <linux/rmap.h>
*/
#include <linux/percpu.h>
#include <linux/smp.h>
//#include <linux/sysctl.h>
#include <linux/cpu.h>
/*
#include <linux/syscalls.h>
#include <linux/pagevec.h>
#include <linux/timer.h>
#include <linux/sched/rt.h>
#include <linux/sched/signal.h>
#include <linux/mm_inline.h>
*/

#include "internal.h"

/*
 * vm_dirty_bytes starts at 0 (disabled) so that it is a function of
 * vm_dirty_ratio * the amount of dirtyable memory
 */
unsigned long vm_dirty_bytes;

/*
 * free highmem will not be subtracted from the total free memory
 * for calculating free ratios if vm_highmem_is_dirtyable is true
 */
int vm_highmem_is_dirtyable;

/*
 * The generator of dirty data starts writeback at this percentage
 */
int vm_dirty_ratio = 20;

static unsigned long highmem_dirtyable_memory(unsigned long total)
{
    return 0;
}

/**
 * global_dirtyable_memory - number of globally dirtyable pages
 *
 * Return: the global number of pages potentially available for dirty
 * page cache.  This is the base value for the global dirty limits.
 */
static unsigned long global_dirtyable_memory(void)
{
    unsigned long x;

    x = global_zone_page_state(NR_FREE_PAGES);
    /*
     * Pages reserved for the kernel should not be considered
     * dirtyable, to prevent a situation where reclaim has to
     * clean pages in order to balance the zones.
     */
    x -= min(x, totalreserve_pages);

    x += global_node_page_state(NR_INACTIVE_FILE);
    x += global_node_page_state(NR_ACTIVE_FILE);

    if (!vm_highmem_is_dirtyable)
        x -= highmem_dirtyable_memory(x);

    return x + 1;   /* Ensure that we never return 0 */
}

/**
 * node_dirtyable_memory - number of dirtyable pages in a node
 * @pgdat: the node
 *
 * Return: the node's number of pages potentially available for dirty
 * page cache.  This is the base value for the per-node dirty limits.
 */
static unsigned long node_dirtyable_memory(struct pglist_data *pgdat)
{
    int z;
    unsigned long nr_pages = 0;

    for (z = 0; z < MAX_NR_ZONES; z++) {
        struct zone *zone = pgdat->node_zones + z;

        if (!populated_zone(zone))
            continue;

        nr_pages += zone_page_state(zone, NR_FREE_PAGES);
    }

    /*
     * Pages reserved for the kernel should not be considered
     * dirtyable, to prevent a situation where reclaim has to
     * clean pages in order to balance the zones.
     */
    nr_pages -= min(nr_pages, pgdat->totalreserve_pages);

    nr_pages += node_page_state(pgdat, NR_INACTIVE_FILE);
    nr_pages += node_page_state(pgdat, NR_ACTIVE_FILE);

    return nr_pages;
}

/**
 * node_dirty_limit - maximum number of dirty pages allowed in a node
 * @pgdat: the node
 *
 * Return: the maximum number of dirty pages allowed in a node, based
 * on the node's dirtyable memory.
 */
static unsigned long node_dirty_limit(struct pglist_data *pgdat)
{
    unsigned long dirty;
    struct task_struct *tsk = current;
    unsigned long node_memory = node_dirtyable_memory(pgdat);

    if (vm_dirty_bytes)
        dirty = DIV_ROUND_UP(vm_dirty_bytes, PAGE_SIZE) *
            node_memory / global_dirtyable_memory();
    else
        dirty = vm_dirty_ratio * node_memory / 100;

    return dirty;
}

/**
 * node_dirty_ok - tells whether a node is within its dirty limits
 * @pgdat: the node to check
 *
 * Return: %true when the dirty pages in @pgdat are within the node's
 * dirty limit, %false if the limit is exceeded.
 */
bool node_dirty_ok(struct pglist_data *pgdat)
{
    unsigned long nr_pages = 0;
    unsigned long limit = node_dirty_limit(pgdat);

    nr_pages += node_page_state(pgdat, NR_FILE_DIRTY);
    nr_pages += node_page_state(pgdat, NR_WRITEBACK);

    return nr_pages <= limit;
}

/*
 * For address_spaces which do not use buffers nor write back.
 */
bool noop_dirty_folio(struct address_space *mapping, struct folio *folio)
{
#if 0
    if (!folio_test_dirty(folio))
        return !folio_test_set_dirty(folio);
#endif
    panic("%s: END!\n", __func__);
    return false;
}
EXPORT_SYMBOL(noop_dirty_folio);

/**
 * folio_wait_writeback - Wait for a folio to finish writeback.
 * @folio: The folio to wait for.
 *
 * If the folio is currently being written back to storage, wait for the
 * I/O to complete.
 *
 * Context: Sleeps.  Must be called in process context and with
 * no spinlocks held.  Caller should hold a reference on the folio.
 * If the folio is not locked, writeback may start again after writeback
 * has finished.
 */
void folio_wait_writeback(struct folio *folio)
{
    while (folio_test_writeback(folio)) {
        folio_wait_bit(folio, PG_writeback);
    }
}
EXPORT_SYMBOL_GPL(folio_wait_writeback);

/**
 * folio_wait_stable() - wait for writeback to finish, if necessary.
 * @folio: The folio to wait on.
 *
 * This function determines if the given folio is related to a backing
 * device that requires folio contents to be held stable during writeback.
 * If so, then it will wait for any pending writeback to complete.
 *
 * Context: Sleeps.  Must be called in process context and with
 * no spinlocks held.  Caller should hold a reference on the folio.
 * If the folio is not locked, writeback may start again after writeback
 * has finished.
 */
void folio_wait_stable(struct folio *folio)
{
    if (folio_inode(folio)->i_sb->s_iflags & SB_I_STABLE_WRITES)
        folio_wait_writeback(folio);
}
EXPORT_SYMBOL_GPL(folio_wait_stable);

/*
 * This cancels just the dirty bit on the kernel page itself, it does NOT
 * actually remove dirty bits on any mmap's that may be around. It also
 * leaves the page tagged dirty, so any sync activity will still find it on
 * the dirty lists, and in particular, clear_page_dirty_for_io() will still
 * look at the dirty bits in the VM.
 *
 * Doing this should *normally* only ever be done when a page is truncated,
 * and is not actually mapped anywhere at all. However, fs/buffer.c does
 * this when it notices that somebody has cleaned out all the buffers on a
 * page without actually doing it through the VM. Can you say "ext3 is
 * horribly ugly"? Thought you could.
 */
void __folio_cancel_dirty(struct folio *folio)
{
    panic("%s: END!\n", __func__);
}

/*
 * Helper function for deaccounting dirty page without writeback.
 *
 * Caller must hold lock_page_memcg().
 */
void folio_account_cleaned(struct folio *folio, struct bdi_writeback *wb)
{
#if 0
    long nr = folio_nr_pages(folio);

    lruvec_stat_mod_folio(folio, NR_FILE_DIRTY, -nr);
    zone_stat_mod_folio(folio, NR_ZONE_WRITE_PENDING, -nr);
    wb_stat_mod(wb, WB_RECLAIMABLE, -nr);
    task_io_account_cancelled_write(nr * PAGE_SIZE);
#endif
    panic("%s: END!\n", __func__);
}

/**
 * folio_mark_dirty - Mark a folio as being modified.
 * @folio: The folio.
 *
 * For folios with a mapping this should be done with the folio lock held
 * for the benefit of asynchronous memory errors who prefer a consistent
 * dirty state. This rule can be broken in some special cases,
 * but should be better not to.
 *
 * Return: True if the folio was newly dirtied, false if it was already dirty.
 */
bool folio_mark_dirty(struct folio *folio)
{
#if 0
    struct address_space *mapping = folio_mapping(folio);

    if (likely(mapping)) {
        /*
         * readahead/lru_deactivate_page could remain
         * PG_readahead/PG_reclaim due to race with folio_end_writeback
         * About readahead, if the folio is written, the flags would be
         * reset. So no problem.
         * About lru_deactivate_page, if the folio is redirtied,
         * the flag will be reset. So no problem. but if the
         * folio is used by readahead it will confuse readahead
         * and make it restart the size rampup process. But it's
         * a trivial problem.
         */
        if (folio_test_reclaim(folio))
            folio_clear_reclaim(folio);
        return mapping->a_ops->dirty_folio(mapping, folio);
    }

    return noop_dirty_folio(mapping, folio);
#endif
    panic("%s: END!\n", __func__);
}
