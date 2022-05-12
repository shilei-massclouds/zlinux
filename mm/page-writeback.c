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
//#include <linux/swap.h>
#include <linux/slab.h>
//#include <linux/pagemap.h>
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
