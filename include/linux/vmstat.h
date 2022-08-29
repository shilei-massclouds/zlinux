/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VMSTAT_H
#define _LINUX_VMSTAT_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/mmzone.h>
#include <linux/vm_event_item.h>
#include <linux/atomic.h>
//#include <linux/static_key.h>
#include <linux/mmdebug.h>

#define sum_zone_node_page_state(node, item)    global_zone_page_state(item)
#define node_page_state(node, item)             global_node_page_state(item)
#define node_page_state_pages(node, item) global_node_page_state_pages(item)

/*
 * Zone and node-based page accounting with per cpu differentials.
 */
extern atomic_long_t vm_zone_stat[NR_VM_ZONE_STAT_ITEMS];
extern atomic_long_t vm_node_stat[NR_VM_NODE_STAT_ITEMS];

/*
 * Light weight per cpu counter implementation.
 *
 * Counters should only be incremented and no critical kernel component
 * should rely on the counter values.
 *
 * Counters are handled completely inline. On many platforms the code
 * generated will simply be the increment of a global address.
 */

struct vm_event_state {
    unsigned long event[NR_VM_EVENT_ITEMS];
};

DECLARE_PER_CPU(struct vm_event_state, vm_event_states);

static inline void fold_vm_numa_events(void)
{
}

/*
 * Returns true if the value is measured in bytes (most vmstat values are
 * measured in pages). This defines the API part, the internal representation
 * might be different.
 */
static __always_inline bool vmstat_item_in_bytes(int idx)
{
    /*
     * Global and per-node slab counters track slab pages.
     * It's expected that changes are multiples of PAGE_SIZE.
     * Internally values are stored in pages.
     *
     * Per-memcg and per-lruvec counters track memory, consumed
     * by individual slab objects. These counters are actually
     * byte-precise.
     */
    return (idx == NR_SLAB_RECLAIMABLE_B || idx == NR_SLAB_UNRECLAIMABLE_B);
}

static inline
unsigned long global_node_page_state_pages(enum node_stat_item item)
{
    long x = atomic_long_read(&vm_node_stat[item]);
    if (x < 0)
        x = 0;
    return x;
}

static inline unsigned long global_node_page_state(enum node_stat_item item)
{
    VM_WARN_ON_ONCE(vmstat_item_in_bytes(item));

    return global_node_page_state_pages(item);
}

static inline unsigned long
zone_page_state(struct zone *zone, enum zone_stat_item item)
{
    long x = atomic_long_read(&zone->vm_stat[item]);
    if (x < 0)
        x = 0;
    return x;
}

static inline unsigned long global_zone_page_state(enum zone_stat_item item)
{
    long x = atomic_long_read(&vm_zone_stat[item]);
    if (x < 0)
        x = 0;
    return x;
}

void __mod_zone_page_state(struct zone *, enum zone_stat_item item, long);

static inline void
zone_page_state_add(long x, struct zone *zone, enum zone_stat_item item)
{
    atomic_long_add(x, &zone->vm_stat[item]);
    atomic_long_add(x, &vm_zone_stat[item]);
}

void mod_node_page_state(struct pglist_data *, enum node_stat_item, long);

static inline void
mod_lruvec_page_state(struct page *page, enum node_stat_item idx, int val)
{
    mod_node_page_state(page_pgdat(page), idx, val);
}

static inline void
node_page_state_add(long x, struct pglist_data *pgdat,
                    enum node_stat_item item)
{
    atomic_long_add(x, &pgdat->vm_stat[item]);
    atomic_long_add(x, &vm_node_stat[item]);
}

static inline void
__mod_zone_freepage_state(struct zone *zone, int nr_pages, int migratetype)
{
    __mod_zone_page_state(zone, NR_FREE_PAGES, nr_pages);
}

static inline void
inc_lruvec_page_state(struct page *page, enum node_stat_item idx)
{
    mod_lruvec_page_state(page, idx, 1);
}

static inline void
dec_lruvec_page_state(struct page *page, enum node_stat_item idx)
{
    mod_lruvec_page_state(page, idx, -1);
}

void __mod_node_page_state(struct pglist_data *,
                           enum node_stat_item item, long);

void __inc_node_page_state(struct page *, enum node_stat_item);
void __dec_node_page_state(struct page *, enum node_stat_item);

static inline void
__mod_lruvec_page_state(struct page *page, enum node_stat_item idx, int val)
{
    __mod_node_page_state(page_pgdat(page), idx, val);
}

static inline void __lruvec_stat_mod_folio(struct folio *folio,
                                           enum node_stat_item idx, int val)
{
    __mod_lruvec_page_state(&folio->page, idx, val);
}

static inline void __mod_lruvec_state(struct lruvec *lruvec,
                                      enum node_stat_item idx, int val)
{
    __mod_node_page_state(lruvec_pgdat(lruvec), idx, val);
}

/*
 * More accurate version that also considers the currently pending
 * deltas. For that we need to loop over all cpus to find the current
 * deltas. There is no synchronization so the result cannot be
 * exactly accurate either.
 */
static inline unsigned long zone_page_state_snapshot(struct zone *zone,
                                                     enum zone_stat_item item)
{
    long x = atomic_long_read(&zone->vm_stat[item]);
    int cpu;
    for_each_online_cpu(cpu)
        x += per_cpu_ptr(zone->per_cpu_zonestats, cpu)->vm_stat_diff[item];

    if (x < 0)
        x = 0;
    return x;
}

/*
 * vm counters are allowed to be racy. Use raw_cpu_ops to avoid the
 * local_irq_disable overhead.
 */
static inline void __count_vm_event(enum vm_event_item item)
{
    raw_cpu_inc(vm_event_states.event[item]);
    if (item == PGFREE)
        pr_info("%s: PGFREE 0(%u)\n", __func__,
                raw_cpu_read(vm_event_states.event[item]));
}

static inline void __count_vm_events(enum vm_event_item item, long delta)
{
    raw_cpu_add(vm_event_states.event[item], delta);
    if (item == PGFREE)
        pr_info("%s: PGFREE 1(%u)\n", __func__,
                raw_cpu_read(vm_event_states.event[item]));
}

void refresh_zone_stat_thresholds(void);

#endif /* _LINUX_VMSTAT_H */
