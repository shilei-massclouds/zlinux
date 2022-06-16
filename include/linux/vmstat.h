/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VMSTAT_H
#define _LINUX_VMSTAT_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/mmzone.h>
//#include <linux/vm_event_item.h>
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

#endif /* _LINUX_VMSTAT_H */
