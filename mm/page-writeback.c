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

/**
 * node_dirty_limit - maximum number of dirty pages allowed in a node
 * @pgdat: the node
 *
 * Return: the maximum number of dirty pages allowed in a node, based
 * on the node's dirtyable memory.
 */
#if 0
static unsigned long node_dirty_limit(struct pglist_data *pgdat)
{
    unsigned long node_memory = node_dirtyable_memory(pgdat);
    struct task_struct *tsk = current;
    unsigned long dirty;

    if (vm_dirty_bytes)
        dirty = DIV_ROUND_UP(vm_dirty_bytes, PAGE_SIZE) *
            node_memory / global_dirtyable_memory();
    else
        dirty = vm_dirty_ratio * node_memory / 100;

    if (rt_task(tsk))
        dirty += dirty / 4;

    return dirty;
}
#endif

/**
 * node_dirty_ok - tells whether a node is within its dirty limits
 * @pgdat: the node to check
 *
 * Return: %true when the dirty pages in @pgdat are within the node's
 * dirty limit, %false if the limit is exceeded.
 */
bool node_dirty_ok(struct pglist_data *pgdat)
{
    return true;
#if 0
    unsigned long nr_pages = 0;
    unsigned long limit = node_dirty_limit(pgdat);

    nr_pages += node_page_state(pgdat, NR_FILE_DIRTY);
    nr_pages += node_page_state(pgdat, NR_WRITEBACK);

    return nr_pages <= limit;
#endif
}
