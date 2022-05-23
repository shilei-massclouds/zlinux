// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/vmstat.c
 *
 *  Manages VM statistics
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  zoned VM statistics
 *  Copyright (C) 2006 Silicon Graphics, Inc.,
 *      Christoph Lameter <christoph@lameter.com>
 *  Copyright (C) 2008-2014 Christoph Lameter
 */
//#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/vmstat.h>
//#include <linux/proc_fs.h>
//#include <linux/seq_file.h>
//#include <linux/debugfs.h>
#include <linux/sched.h>
//#include <linux/math64.h>
#include <linux/writeback.h>
#if 0
#include <linux/compaction.h>
#include <linux/mm_inline.h>
#include <linux/page_ext.h>
#include <linux/page_owner.h>
#endif

#include "internal.h"

/*
 * Manage combined zone based / global counters
 *
 * vm_stat contains the global counters
 */
atomic_long_t vm_zone_stat[NR_VM_ZONE_STAT_ITEMS] __cacheline_aligned_in_smp;
atomic_long_t vm_node_stat[NR_VM_NODE_STAT_ITEMS] __cacheline_aligned_in_smp;
EXPORT_SYMBOL(vm_zone_stat);
EXPORT_SYMBOL(vm_node_stat);

/*
 * For use when we know that interrupts are disabled,
 * or when we know that preemption is disabled and that
 * particular counter cannot be updated from interrupt context.
 */
void __mod_zone_page_state(struct zone *zone,
                           enum zone_stat_item item, long delta)
{
    long x;
    long t;
    struct per_cpu_zonestat __percpu *pcp = zone->per_cpu_zonestats;
    s8 __percpu *p = pcp->vm_stat_diff + item;

    x = delta + __this_cpu_read(*p);

    t = __this_cpu_read(pcp->stat_threshold);

    if (unlikely(abs(x) > t)) {
        zone_page_state_add(x, zone, item);
        x = 0;
    }
    __this_cpu_write(*p, x);
}
EXPORT_SYMBOL(__mod_zone_page_state);

void __mod_node_page_state(struct pglist_data *pgdat,
                           enum node_stat_item item, long delta)
{
    long x;
    long t;
    struct per_cpu_nodestat __percpu *pcp = pgdat->per_cpu_nodestats;
    s8 __percpu *p = pcp->vm_node_stat_diff + item;

    if (vmstat_item_in_bytes(item)) {
        /*
         * Only cgroups use subpage accounting right now; at
         * the global level, these items still change in
         * multiples of whole pages. Store them as pages
         * internally to keep the per-cpu counters compact.
         */
        VM_WARN_ON_ONCE(delta & (PAGE_SIZE - 1));
        delta >>= PAGE_SHIFT;
    }

    x = delta + __this_cpu_read(*p);

    t = __this_cpu_read(pcp->stat_threshold);

    if (unlikely(abs(x) > t)) {
        node_page_state_add(x, pgdat, item);
        x = 0;
    }
    __this_cpu_write(*p, x);
}

void mod_node_page_state(struct pglist_data *pgdat,
                         enum node_stat_item item, long delta)
{
    unsigned long flags;

    local_irq_save(flags);
    __mod_node_page_state(pgdat, item, delta);
    local_irq_restore(flags);
}
EXPORT_SYMBOL(mod_node_page_state);
