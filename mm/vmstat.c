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

DEFINE_PER_CPU(struct vm_event_state, vm_event_states) = {{0}};
EXPORT_PER_CPU_SYMBOL(vm_event_states);

int calculate_normal_threshold(struct zone *zone)
{
    int threshold;
    int mem;    /* memory in 128 MB units */

    /*
     * The threshold scales with the number of processors and the amount
     * of memory per zone. More memory means that we can defer updates for
     * longer, more processors could lead to more contention.
     * fls() is used to have a cheap way of logarithmic scaling.
     *
     * Some sample thresholds:
     *
     * Threshold    Processors  (fls)   Zonesize    fls(mem)+1
     * ------------------------------------------------------------------
     * 8        1       1   0.9-1 GB    4
     * 16       2       2   0.9-1 GB    4
     * 20       2       2   1-2 GB      5
     * 24       2       2   2-4 GB      6
     * 28       2       2   4-8 GB      7
     * 32       2       2   8-16 GB     8
     * 4        2       2   <128M       1
     * 30       4       3   2-4 GB      5
     * 48       4       3   8-16 GB     8
     * 32       8       4   1-2 GB      4
     * 32       8       4   0.9-1GB     4
     * 10       16      5   <128M       1
     * 40       16      5   900M        4
     * 70       64      7   2-4 GB      5
     * 84       64      7   4-8 GB      6
     * 108      512     9   4-8 GB      6
     * 125      1024        10  8-16 GB     8
     * 125      1024        10  16-32 GB    9
     */

    mem = zone_managed_pages(zone) >> (27 - PAGE_SHIFT);

    threshold = 2 * fls(num_online_cpus()) * (1 + fls(mem));

    /*
     * Maximum threshold is 125
     */
    threshold = min(125, threshold);

    return threshold;
}

/*
 * Refresh the thresholds for each zone.
 */
void refresh_zone_stat_thresholds(void)
{
    struct pglist_data *pgdat;
    struct zone *zone;
    int cpu;
    int threshold;

    /* Zero current pgdat thresholds */
    for_each_online_pgdat(pgdat) {
        for_each_online_cpu(cpu) {
            per_cpu_ptr(pgdat->per_cpu_nodestats, cpu)->stat_threshold = 0;
        }
    }

    for_each_populated_zone(zone) {
        struct pglist_data *pgdat = zone->zone_pgdat;
        unsigned long max_drift, tolerate_drift;

        threshold = calculate_normal_threshold(zone);

        for_each_online_cpu(cpu) {
            int pgdat_threshold;

            per_cpu_ptr(zone->per_cpu_zonestats, cpu)->stat_threshold =
                threshold;

            /* Base nodestat threshold on the largest populated zone. */
            pgdat_threshold =
                per_cpu_ptr(pgdat->per_cpu_nodestats, cpu)->stat_threshold;
            per_cpu_ptr(pgdat->per_cpu_nodestats, cpu)->stat_threshold =
                max(threshold, pgdat_threshold);
        }

        /*
         * Only set percpu_drift_mark if there is a danger that
         * NR_FREE_PAGES reports the low watermark is ok when in fact
         * the min watermark could be breached by an allocation
         */
        tolerate_drift = low_wmark_pages(zone) - min_wmark_pages(zone);
        max_drift = num_online_cpus() * threshold;
        if (max_drift > tolerate_drift)
            zone->percpu_drift_mark = high_wmark_pages(zone) + max_drift;
    }
}

int calculate_pressure_threshold(struct zone *zone)
{
    int threshold;
    int watermark_distance;

    /*
     * As vmstats are not up to date, there is drift between the estimated
     * and real values. For high thresholds and a high number of CPUs, it
     * is possible for the min watermark to be breached while the estimated
     * value looks fine. The pressure threshold is a reduced value such
     * that even the maximum amount of drift will not accidentally breach
     * the min watermark
     */
    watermark_distance = low_wmark_pages(zone) - min_wmark_pages(zone);
    threshold = max(1, (int)(watermark_distance / num_online_cpus()));

    /*
     * Maximum threshold is 125
     */
    threshold = min(125, threshold);

    return threshold;
}

void
set_pgdat_percpu_threshold(pg_data_t *pgdat,
                           int (*calculate_pressure)(struct zone *))
{
    struct zone *zone;
    int cpu;
    int threshold;
    int i;

    for (i = 0; i < pgdat->nr_zones; i++) {
        zone = &pgdat->node_zones[i];
        if (!zone->percpu_drift_mark)
            continue;

        threshold = (*calculate_pressure)(zone);
        for_each_online_cpu(cpu)
            per_cpu_ptr(zone->per_cpu_zonestats, cpu)->stat_threshold
                            = threshold;
    }
}
