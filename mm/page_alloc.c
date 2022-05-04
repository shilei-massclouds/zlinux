// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/page_alloc.c
 *
 *  Manages the free list, the system allocates free pages here.
 *  Note that kmalloc() lives in slab.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 *  Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
 *          (lots of bits borrowed from Ingo Molnar & Andrew Morton)
 */

#include <linux/stddef.h>
#include <linux/mm.h>
/*
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/jiffies.h>
*/
#include <linux/memblock.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
/*
#include <linux/kasan.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
*/
#include <linux/slab.h>
/*
#include <linux/ratelimit.h>
#include <linux/oom.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
*/
#include <linux/cpu.h>
/*
#include <linux/cpuset.h>
#include <linux/memory_hotplug.h>
#include <linux/vmalloc.h>
#include <linux/vmstat.h>
#include <linux/mempolicy.h>
#include <linux/memremap.h>
#include <linux/stop_machine.h>
#include <linux/random.h>
#include <linux/sort.h>
*/
#include <linux/nodemask.h>
#include <linux/pfn.h>
/*
#include <linux/backing-dev.h>
#include <linux/fault-inject.h>
#include <linux/page-isolation.h>
#include <linux/debugobjects.h>
#include <linux/kmemleak.h>
#include <linux/compaction.h>
#include <trace/events/kmem.h>
#include <trace/events/oom.h>
#include <linux/prefetch.h>
#include <linux/mm_inline.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/sched/rt.h>
#include <linux/sched/mm.h>
#include <linux/page_owner.h>
*/
#include <linux/kthread.h>
/*
#include <linux/memcontrol.h>
#include <linux/ftrace.h>
#include <linux/lockdep.h>
#include <linux/nmi.h>
#include <linux/psi.h>
#include <linux/padata.h>
*/

#include <linux/string.h>
#include <linux/percpu.h>

#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/div64.h>
#include "internal.h"
/*
#include "shuffle.h"
#include "page_reporting.h"
*/

static unsigned long nr_kernel_pages __initdata;
static unsigned long nr_all_pages __initdata;
static unsigned long dma_reserve __initdata;

static unsigned long
arch_zone_lowest_possible_pfn[MAX_NR_ZONES] __initdata;
static unsigned long
arch_zone_highest_possible_pfn[MAX_NR_ZONES] __initdata;

static unsigned long zone_movable_pfn[MAX_NUMNODES] __initdata;

static char * const zone_names[MAX_NR_ZONES] = {
#ifdef CONFIG_ZONE_DMA32
     "DMA32",
#endif
     "Normal",
     "Movable",
};

DEFINE_PER_CPU(struct per_cpu_nodestat, boot_nodestats);

/**
 * find_min_pfn_with_active_regions - Find the minimum PFN registered
 *
 * Return: the minimum PFN based on information provided via
 * memblock_set_node().
 */
unsigned long __init find_min_pfn_with_active_regions(void)
{
    return PHYS_PFN(memblock_start_of_DRAM());
}

/*
 * Some architecturs, e.g. ARC may have ZONE_HIGHMEM below ZONE_NORMAL. For
 * such cases we allow max_zone_pfn sorted in the descending order
 */
bool __weak arch_has_descending_max_zone_pfns(void)
{
    return false;
}

/*
 * Return the number of pages a zone spans in a node, including holes
 * present_pages = zone_spanned_pages_in_node() - zone_absent_pages_in_node()
 */
static unsigned long __init
zone_spanned_pages_in_node(int nid,
                           unsigned long zone_type,
                           unsigned long node_start_pfn, unsigned long node_end_pfn,
                           unsigned long *zone_start_pfn, unsigned long *zone_end_pfn)
{
    unsigned long zone_low = arch_zone_lowest_possible_pfn[zone_type];
    unsigned long zone_high = arch_zone_highest_possible_pfn[zone_type];
    /* When hotadd a new node from cpu_up(), the node should be empty */
    if (!node_start_pfn && !node_end_pfn)
        return 0;

    /* Get the start and end of the zone */
    *zone_start_pfn = clamp(node_start_pfn, zone_low, zone_high);
    *zone_end_pfn = clamp(node_end_pfn, zone_low, zone_high);

    /*
    adjust_zone_range_for_zone_movable(nid, zone_type,
                                       node_start_pfn, node_end_pfn,
                                       zone_start_pfn, zone_end_pfn);
    */

    /* Check that this node has pages within the zone's required range */
    if (*zone_end_pfn < node_start_pfn || *zone_start_pfn > node_end_pfn)
        return 0;

    /* Move the zone boundaries inside the node if necessary */
    *zone_end_pfn = min(*zone_end_pfn, node_end_pfn);
    *zone_start_pfn = max(*zone_start_pfn, node_start_pfn);

    /* Return the spanned pages */
    return *zone_end_pfn - *zone_start_pfn;
}

/*
 * Return the number of holes in a range on a node. If nid is MAX_NUMNODES,
 * then all holes in the requested range will be accounted for.
 */
unsigned long __init
__absent_pages_in_range(int nid, unsigned long range_start_pfn, unsigned long range_end_pfn)
{
    int i;
    unsigned long start_pfn, end_pfn;
    unsigned long nr_absent = range_end_pfn - range_start_pfn;

    for_each_mem_pfn_range(i, nid, &start_pfn, &end_pfn, NULL) {
        start_pfn = clamp(start_pfn, range_start_pfn, range_end_pfn);
        end_pfn = clamp(end_pfn, range_start_pfn, range_end_pfn);
        nr_absent -= end_pfn - start_pfn;
    }
    return nr_absent;
}

/* Return the number of page frames in holes in a zone on a node */
static unsigned long __init
zone_absent_pages_in_node(int nid, unsigned long zone_type,
                          unsigned long node_start_pfn, unsigned long node_end_pfn)
{
    unsigned long nr_absent;
    unsigned long zone_start_pfn, zone_end_pfn;
    unsigned long zone_low = arch_zone_lowest_possible_pfn[zone_type];
    unsigned long zone_high = arch_zone_highest_possible_pfn[zone_type];

    /* When hotadd a new node from cpu_up(), the node should be empty */
    if (!node_start_pfn && !node_end_pfn)
        return 0;

    zone_start_pfn = clamp(node_start_pfn, zone_low, zone_high);
    zone_end_pfn = clamp(node_end_pfn, zone_low, zone_high);

    /*
    adjust_zone_range_for_zone_movable(nid, zone_type,
            node_start_pfn, node_end_pfn,
            &zone_start_pfn, &zone_end_pfn);
    */

    nr_absent = __absent_pages_in_range(nid, zone_start_pfn, zone_end_pfn);
    return nr_absent;
}

static void __init
calculate_node_totalpages(struct pglist_data *pgdat,
                          unsigned long node_start_pfn, unsigned long node_end_pfn)
{
    enum zone_type i;
    unsigned long realtotalpages = 0, totalpages = 0;

    for (i = 0; i < MAX_NR_ZONES; i++) {
        unsigned long size, real_size;
        unsigned long spanned, absent;
        unsigned long zone_start_pfn, zone_end_pfn;
        struct zone *zone = pgdat->node_zones + i;

        spanned = zone_spanned_pages_in_node(pgdat->node_id, i,
                                             node_start_pfn, node_end_pfn,
                                             &zone_start_pfn, &zone_end_pfn);

        absent = zone_absent_pages_in_node(pgdat->node_id, i,
                                           node_start_pfn, node_end_pfn);

        size = spanned;
        real_size = size - absent;

        if (size)
            zone->zone_start_pfn = zone_start_pfn;
        else
            zone->zone_start_pfn = 0;

        zone->spanned_pages = size;
        zone->present_pages = real_size;

        totalpages += size;
        realtotalpages += real_size;
    }

    pgdat->node_spanned_pages = totalpages;
    pgdat->node_present_pages = realtotalpages;
    pr_debug("On node %d totalpages: %lu\n", pgdat->node_id, realtotalpages);
}

void __init *
memmap_alloc(phys_addr_t size, phys_addr_t align,
             phys_addr_t min_addr, int nid, bool exact_nid)
{
    void *ptr;

    if (exact_nid)
        ptr = memblock_alloc_exact_nid_raw(size, align, min_addr,
                                           MEMBLOCK_ALLOC_ACCESSIBLE, nid);
    else
        ptr = memblock_alloc_try_nid_raw(size, align, min_addr,
                                         MEMBLOCK_ALLOC_ACCESSIBLE, nid);

    if (ptr && size > 0)
        page_init_poison(ptr, size);

    return ptr;
}

static void __init alloc_node_mem_map(struct pglist_data *pgdat)
{
    unsigned long __maybe_unused start = 0;
    unsigned long __maybe_unused offset = 0;

    /* Skip empty nodes */
    if (!pgdat->node_spanned_pages)
        return;

    start = pgdat->node_start_pfn & ~(MAX_ORDER_NR_PAGES - 1);
    offset = pgdat->node_start_pfn - start;
    /* ia64 gets its own node_mem_map, before this, without bootmem */
    if (!pgdat->node_mem_map) {
        struct page *map;
        unsigned long size, end;

        /*
         * The zone's endpoints aren't required to be MAX_ORDER
         * aligned but the node_mem_map endpoints must be in order
         * for the buddy allocator to function correctly.
         */
        end = pgdat_end_pfn(pgdat);
        end = ALIGN(end, MAX_ORDER_NR_PAGES);
        size = (end - start) * sizeof(struct page);
        map = memmap_alloc(size, SMP_CACHE_BYTES, MEMBLOCK_LOW_LIMIT, pgdat->node_id, false);
        if (!map)
            panic("Failed to allocate %ld bytes for node %d memory map\n",
                  size, pgdat->node_id);
        pgdat->node_mem_map = map + offset;
    }
    pr_debug("%s: node %d, pgdat %08lx, node_mem_map %08lx\n",
             __func__, pgdat->node_id, (unsigned long)pgdat,
             (unsigned long)pgdat->node_mem_map);

    /*
     * With no DISCONTIG, the global mem_map is just set as node 0's
     */
    if (pgdat == NODE_DATA(0)) {
        mem_map = NODE_DATA(0)->node_mem_map;
        if (page_to_pfn(mem_map) != pgdat->node_start_pfn)
            mem_map -= offset;
    }
}

static void __meminit pgdat_init_internals(struct pglist_data *pgdat)
{
}

static unsigned long __init
calc_memmap_size(unsigned long spanned_pages, unsigned long present_pages)
{
    unsigned long pages = spanned_pages;

    return PAGE_ALIGN(pages * sizeof(struct page)) >> PAGE_SHIFT;
}

static __meminit void zone_pcp_init(struct zone *zone)
{
    /*
     * per cpu subsystem is not up at this point. The following code
     * relies on the ability of the linker to provide the
     * offset of a (static) per cpu variable into the per cpu area.
     */
#if 0
    zone->per_cpu_pageset = &boot_pageset;
    zone->per_cpu_zonestats = &boot_zonestats;
    zone->pageset_high = BOOT_PAGESET_HIGH;
    zone->pageset_batch = BOOT_PAGESET_BATCH;

    if (populated_zone(zone))
        pr_debug("  %s zone: %lu pages, LIFO batch:%u\n",
                 zone->name, zone->present_pages, zone_batchsize(zone));
#endif
}

static void __meminit
zone_init_internals(struct zone *zone, enum zone_type idx, int nid,
                    unsigned long remaining_pages)
{
    atomic_long_set(&zone->managed_pages, remaining_pages);
    zone_set_nid(zone, nid);
    zone->name = zone_names[idx];
    zone->zone_pgdat = NODE_DATA(nid);
    spin_lock_init(&zone->lock);
    zone_pcp_init(zone);
}

/**
 * set_dma_reserve - set the specified number of pages reserved in the first zone
 * @new_dma_reserve: The number of pages to mark reserved
 *
 * The per-cpu batchsize and zone watermarks are determined by managed_pages.
 * In the DMA zone, a significant percentage may be consumed by kernel image
 * and other unfreeable allocations which can skew the watermarks badly. This
 * function may optionally be used to account for unfreeable pages in the
 * first zone (e.g., ZONE_DMA). The effect will be lower watermarks and
 * smaller per-cpu batchsize.
 */
void __init set_dma_reserve(unsigned long new_dma_reserve)
{
    dma_reserve = new_dma_reserve;
}

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 *
 * NOTE: pgdat should get zeroed by caller.
 * NOTE: this function is only called during early init.
 */
static void __init free_area_init_core(struct pglist_data *pgdat)
{
    enum zone_type j;
    int nid = pgdat->node_id;

    pgdat_init_internals(pgdat);
    pgdat->per_cpu_nodestats = &boot_nodestats;

    for (j = 0; j < MAX_NR_ZONES; j++) {
        unsigned long size, freesize, memmap_pages;
        struct zone *zone = pgdat->node_zones + j;

        size = zone->spanned_pages;
        freesize = zone->present_pages;

        /*
         * Adjust freesize so that it accounts for how much memory
         * is used by this zone for memmap. This affects the watermark
         * and per-cpu initialisations
         */
        memmap_pages = calc_memmap_size(size, freesize);
        if (freesize >= memmap_pages) {
            freesize -= memmap_pages;
            if (memmap_pages)
                pr_debug("  %s zone: %lu pages used for memmap\n",
                         zone_names[j], memmap_pages);
        } else {
            pr_warn("  %s zone: %lu memmap pages exceeds freesize %lu\n",
                    zone_names[j], memmap_pages, freesize);
        }

        /* Account for reserved pages */
        if (j == 0 && freesize > dma_reserve) {
            freesize -= dma_reserve;
            pr_debug("  %s zone: %lu pages reserved\n",
                     zone_names[0], dma_reserve);
        }

        nr_kernel_pages += freesize;
        /* Charge for highmem memmap if there are enough kernel pages */
        if (nr_kernel_pages > memmap_pages * 2)
            nr_kernel_pages -= memmap_pages;
        nr_all_pages += freesize;

        /*
         * Set an approximate value for lowmem here, it will be adjusted
         * when the bootmem allocator frees pages into the buddy system.
         * And all highmem pages will be managed by the buddy system.
         */
        zone_init_internals(zone, j, nid, freesize);

#if 0
        if (!size)
            continue;

        set_pageblock_order();
        setup_usemap(zone);
        init_currently_empty_zone(zone, zone->zone_start_pfn, size);
#endif

        panic("%s: step1\n", __func__);
    }

    panic("%s: END\n", __func__);
}

static void __init free_area_init_node(int nid)
{
    unsigned long start_pfn = 0;
    unsigned long end_pfn = 0;
    pg_data_t *pgdat = NODE_DATA(nid);

    /* pg_data_t should be reset to zero when it's allocated */
    WARN_ON(pgdat->nr_zones || pgdat->kswapd_highest_zoneidx);

    get_pfn_range_for_nid(nid, &start_pfn, &end_pfn);

    pgdat->node_id = nid;
    pgdat->node_start_pfn = start_pfn;
    pgdat->per_cpu_nodestats = NULL;

    if (start_pfn != end_pfn) {
        pr_info("Initmem setup node %d [mem %#018Lx-%#018Lx]\n",
                nid, (u64)start_pfn << PAGE_SHIFT,
                end_pfn ? ((u64)end_pfn << PAGE_SHIFT) - 1 : 0);
    } else {
        pr_info("Initmem setup node %d as memoryless\n", nid);
    }

    calculate_node_totalpages(pgdat, start_pfn, end_pfn);

    alloc_node_mem_map(pgdat);

    free_area_init_core(pgdat);
}

/**
 * free_area_init - Initialise all pg_data_t and zone data
 * @max_zone_pfn: an array of max PFNs for each zone
 *
 * This will call free_area_init_node() for each active node in the system.
 * Using the page ranges provided by memblock_set_node(), the size of each
 * zone in each node and their holes is calculated. If the maximum PFN
 * between two adjacent zones match, it is assumed that the zone is empty.
 * For example, if arch_max_dma_pfn == arch_max_dma32_pfn, it is assumed
 * that arch_max_dma32_pfn has no pages. It is also assumed that a zone
 * starts where the previous one ended. For example, ZONE_DMA32 starts
 * at arch_max_dma_pfn.
 */
void __init free_area_init(unsigned long *max_zone_pfn)
{
    unsigned long start_pfn, end_pfn;
    int i, nid, zone;
    bool descending;

    /* Record where the zone boundaries are */
    memset(arch_zone_lowest_possible_pfn, 0,
           sizeof(arch_zone_lowest_possible_pfn));
    memset(arch_zone_highest_possible_pfn, 0,
           sizeof(arch_zone_highest_possible_pfn));

    start_pfn = find_min_pfn_with_active_regions();
    descending = arch_has_descending_max_zone_pfns();

    for (i = 0; i < MAX_NR_ZONES; i++) {
        if (descending)
            zone = MAX_NR_ZONES - i - 1;
        else
            zone = i;

        if (zone == ZONE_MOVABLE)
            continue;

        end_pfn = max(max_zone_pfn[zone], start_pfn);
        arch_zone_lowest_possible_pfn[zone] = start_pfn;
        arch_zone_highest_possible_pfn[zone] = end_pfn;

        start_pfn = end_pfn;
    }

    /* Find the PFNs that ZONE_MOVABLE begins at in each node */
    memset(zone_movable_pfn, 0, sizeof(zone_movable_pfn));
    //find_zone_movable_pfns_for_nodes();

    /* Print out the zone ranges */
    pr_info("Zone ranges:\n");
    for (i = 0; i < MAX_NR_ZONES; i++) {
        if (i == ZONE_MOVABLE)
            continue;
        pr_info("  %-8s ", zone_names[i]);
        if (arch_zone_lowest_possible_pfn[i] == arch_zone_highest_possible_pfn[i])
            pr_cont("empty\n");
        else
            pr_cont("[mem %#018Lx-%#018Lx]\n",
                    (u64)arch_zone_lowest_possible_pfn[i] << PAGE_SHIFT,
                    ((u64)arch_zone_highest_possible_pfn[i] << PAGE_SHIFT) - 1);
    }

    /* Print out the PFNs ZONE_MOVABLE begins at in each node */
    pr_info("Movable zone start for each node\n");
    for (i = 0; i < MAX_NUMNODES; i++) {
        if (zone_movable_pfn[i])
            pr_info("  Node %d: %#018Lx\n", i, (u64)zone_movable_pfn[i] << PAGE_SHIFT);
    }

    /*
     * Print out the early node map, and initialize the
     * subsection-map relative to active online memory ranges to
     * enable future "sub-section" extensions of the memory map.
     */
    pr_info("Early memory node ranges\n");
    for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
        pr_info("  node %3d: [mem %#018Lx-%#018Lx]\n", nid,
                (u64)start_pfn << PAGE_SHIFT,
                ((u64)end_pfn << PAGE_SHIFT) - 1);
    }

    /* Initialise every node */
    setup_nr_node_ids();
    for_each_node(nid) {
        pg_data_t *pgdat;

        if (!node_online(nid)) {
            panic("Initializing node %d as memoryless\n", nid);
        }

        pgdat = NODE_DATA(nid);
        free_area_init_node(nid);

#if 0
        /* Any memory on that node */
        if (pgdat->node_present_pages)
            node_set_state(nid, N_MEMORY);
        check_for_memory(pgdat, nid);
#endif
    }

    panic("%s: start_pfn(%lx)\n", __func__, start_pfn);
}

/**
 * get_pfn_range_for_nid - Return the start and end page frames for a node
 * @nid: The nid to return the range for.
 *  If MAX_NUMNODES, the min and max PFN are returned.
 * @start_pfn: Passed by reference. On return, it will have the node start_pfn.
 * @end_pfn: Passed by reference. On return, it will have the node end_pfn.
 *
 * It returns the start and end page frame of a node based on information
 * provided by memblock_set_node(). If called for a node
 * with no available memory, a warning is printed and the start and end
 * PFNs will be 0.
 */
void __init get_pfn_range_for_nid(unsigned int nid,
                                  unsigned long *start_pfn,
                                  unsigned long *end_pfn)
{
    unsigned long this_start_pfn, this_end_pfn;
    int i;

    *start_pfn = -1UL;
    *end_pfn = 0;

    for_each_mem_pfn_range(i, nid, &this_start_pfn, &this_end_pfn, NULL) {
        *start_pfn = min(*start_pfn, this_start_pfn);
        *end_pfn = max(*end_pfn, this_end_pfn);
    }

    if (*start_pfn == -1UL)
        *start_pfn = 0;
}
