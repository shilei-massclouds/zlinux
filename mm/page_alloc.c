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

#include <linux/mm.h>
#include <linux/highmem.h>
/*
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
#include <linux/stop_machine.h>
#include <linux/random.h>
#include <linux/sort.h>
*/
#include <linux/memremap.h>
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
#include <linux/mm_inline.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/sched/rt.h>
#include <linux/page_owner.h>
*/
#include <linux/prefetch.h>
#include <linux/kthread.h>
#include <linux/sched/mm.h>
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
#include <linux/compat.h>
#include <linux/writeback.h>

#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/div64.h>
#include "internal.h"
/*
#include "shuffle.h"
#include "page_reporting.h"
*/

/* Free Page Internal flags: for internal, non-pcp variants of free_pages(). */
typedef int __bitwise fpi_t;

/* No special request */
#define FPI_NONE        ((__force fpi_t)0)

/*
 * Place the (possibly merged) page to the tail of the freelist. Will ignore
 * page shuffling (relevant code - e.g., memory onlining - is expected to
 * shuffle the whole zone).
 *
 * Note: No code should rely on this flag for correctness - it's purely
 *       to allow for optimizations when handing back either fresh pages
 *       (memory onlining) or untouched pages (page isolation, free page
 *       reporting).
 */
#define FPI_TO_TAIL ((__force fpi_t)BIT(1))

/*
 * Don't poison memory with KASAN (only for the tag-based modes).
 * During boot, all non-reserved memblock memory is exposed to page_alloc.
 * Poisoning all that memory lengthens boot time, especially on systems with
 * large amount of RAM. This flag is used to skip that poisoning.
 * This is only done for the tag-based KASAN modes, as those are able to
 * detect memory corruptions with the memory tags assigned by default.
 * All memory allocated normally after boot gets poisoned as usual.
 */
#define FPI_SKIP_KASAN_POISON   ((__force fpi_t)BIT(2))

int page_group_by_mobility_disabled __read_mostly;

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

gfp_t gfp_allowed_mask __read_mostly = GFP_BOOT_MASK;

/* These effectively disable the pcplists in the boot pageset completely */
#define BOOT_PAGESET_HIGH   0
#define BOOT_PAGESET_BATCH  1
static DEFINE_PER_CPU(struct per_cpu_pages, boot_pageset);
static DEFINE_PER_CPU(struct per_cpu_zonestat, boot_zonestats);
DEFINE_PER_CPU(struct per_cpu_nodestat, boot_nodestats);

//#define MAX_NODE_LOAD (nr_online_nodes)
//static int node_load[MAX_NUMNODES];

struct pagesets {
    local_lock_t lock;
};
static DEFINE_PER_CPU(struct pagesets, pagesets) = {
    .lock = INIT_LOCAL_LOCK(lock),
};

/*
 * This array describes the order lists are fallen back to when
 * the free lists for the desirable migrate type are depleted
 */
static int fallbacks[MIGRATE_TYPES][3] = {
    [MIGRATE_UNMOVABLE]   = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE,   MIGRATE_TYPES },
    [MIGRATE_MOVABLE]     = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE, MIGRATE_TYPES },
    [MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE,   MIGRATE_MOVABLE,   MIGRATE_TYPES },
};

atomic_long_t _totalram_pages __read_mostly;
EXPORT_SYMBOL(_totalram_pages);

unsigned long totalreserve_pages __read_mostly;

DEFINE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);
EXPORT_SYMBOL(init_on_alloc);

/* movable_zone is the "real" zone pages in ZONE_MOVABLE are taken from */
int movable_zone;
EXPORT_SYMBOL(movable_zone);

static inline unsigned int order_to_pindex(int migratetype, int order)
{
    int base = order;

    VM_BUG_ON(order > PAGE_ALLOC_COSTLY_ORDER);
    return (MIGRATE_PCPTYPES * base) + migratetype;
}

static inline int pindex_to_order(unsigned int pindex)
{
    int order = pindex / MIGRATE_PCPTYPES;

    VM_BUG_ON(order > PAGE_ALLOC_COSTLY_ORDER);
    return order;
}

/*
 * A cached value of the page's pageblock's migratetype, used when the page is
 * put on a pcplist. Used to avoid the pageblock migratetype lookup when
 * freeing from pcplists in most cases, at the cost of possibly becoming stale.
 * Also the migratetype set in the page does not necessarily match the pcplist
 * index, e.g. page might have MIGRATE_CMA set but be on a pcplist with any
 * other index - this ensures that it will be put on the correct CMA freelist.
 */
static inline int get_pcppage_migratetype(struct page *page)
{
    return page->index;
}

static inline void
set_pcppage_migratetype(struct page *page, int migratetype)
{
    page->index = migratetype;
}

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
                           unsigned long node_start_pfn,
                           unsigned long node_end_pfn,
                           unsigned long *zone_start_pfn,
                           unsigned long *zone_end_pfn)
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
                          unsigned long node_start_pfn,
                          unsigned long node_end_pfn)
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

static int zone_batchsize(struct zone *zone)
{
    int batch;

    /*
     * The number of pages to batch allocate is either ~0.1%
     * of the zone or 1MB, whichever is smaller. The batch
     * size is striking a balance between allocation latency
     * and zone lock contention.
     */
    batch = min(zone_managed_pages(zone) >> 10, (1024 * 1024) / PAGE_SIZE);
    batch /= 4;     /* We effectively *= 4 below */
    if (batch < 1)
        batch = 1;

    /*
     * Clamp the batch to a 2^n - 1 value. Having a power
     * of 2 value was found to be more likely to have
     * suboptimal cache aliasing properties in some cases.
     *
     * For example if 2 tasks are alternately allocating
     * batches of pages, one task can end up with a lot
     * of pages of one half of the possible page colors
     * and the other with pages of the other colors.
     */
    batch = rounddown_pow_of_two(batch + batch/2) - 1;

    return batch;
}

static __meminit void zone_pcp_init(struct zone *zone)
{
    /*
     * per cpu subsystem is not up at this point. The following code
     * relies on the ability of the linker to provide the
     * offset of a (static) per cpu variable into the per cpu area.
     */
    zone->per_cpu_pageset = &boot_pageset;
    zone->per_cpu_zonestats = &boot_zonestats;
    zone->pageset_high = BOOT_PAGESET_HIGH;
    zone->pageset_batch = BOOT_PAGESET_BATCH;

    if (populated_zone(zone))
        pr_debug("  %s zone: %lu pages, LIFO batch:%u\n",
                 zone->name, zone->present_pages, zone_batchsize(zone));
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
 * Calculate the size of the zone->blockflags rounded to an unsigned long
 * Start by making sure zonesize is a multiple of pageblock_order by rounding
 * up. Then use 1 NR_PAGEBLOCK_BITS worth of bits per pageblock, finally
 * round what is now in bits to nearest long in bits, then return it in
 * bytes.
 */
static unsigned long __init
usemap_size(unsigned long zone_start_pfn, unsigned long zonesize)
{
    unsigned long usemapsize;

    zonesize += zone_start_pfn & (pageblock_nr_pages-1);
    usemapsize = roundup(zonesize, pageblock_nr_pages);
    usemapsize = usemapsize >> pageblock_order;
    usemapsize *= NR_PAGEBLOCK_BITS;
    usemapsize = roundup(usemapsize, 8 * sizeof(unsigned long));

    return usemapsize / 8;
}

static void __ref setup_usemap(struct zone *zone)
{
    unsigned long usemapsize = usemap_size(zone->zone_start_pfn,
                                           zone->spanned_pages);
    zone->pageblock_flags = NULL;
    if (usemapsize) {
        zone->pageblock_flags =
            memblock_alloc_node(usemapsize, SMP_CACHE_BYTES, zone_to_nid(zone));
        if (!zone->pageblock_flags)
            panic("Failed to allocate %ld bytes for zone %s pageblock flags on node %d\n",
                  usemapsize, zone->name, zone_to_nid(zone));
    }
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

        if (!size)
            continue;

        setup_usemap(zone);
        init_currently_empty_zone(zone, zone->zone_start_pfn, size);
    }
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

/* Any regular or high memory on that node ? */
static void check_for_memory(pg_data_t *pgdat, int nid)
{
    enum zone_type zone_type;

    for (zone_type = 0; zone_type <= ZONE_MOVABLE - 1; zone_type++) {
        struct zone *zone = &pgdat->node_zones[zone_type];
        if (populated_zone(zone)) {
            if (zone_type <= ZONE_NORMAL)
                node_set_state(nid, N_NORMAL_MEMORY);
            break;
        }
    }
}

static void __meminit
__init_single_page(struct page *page, unsigned long pfn,
                   unsigned long zone, int nid)
{
    mm_zero_struct_page(page);
    set_page_links(page, zone, nid, pfn);
    init_page_count(page);
    page_mapcount_reset(page);
    page_cpupid_reset_last(page);

    INIT_LIST_HEAD(&page->lru);
}

/* Return a pointer to the bitmap storing bits affecting a block of pages */
static inline unsigned long *
get_pageblock_bitmap(const struct page *page, unsigned long pfn)
{
    return page_zone(page)->pageblock_flags;
}

static inline int pfn_to_bitidx(const struct page *page, unsigned long pfn)
{
    pfn = pfn - round_down(page_zone(page)->zone_start_pfn, pageblock_nr_pages);
    return (pfn >> pageblock_order) * NR_PAGEBLOCK_BITS;
}

/**
 * set_pfnblock_flags_mask - Set the requested group of flags for a pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @flags: The flags to set
 * @pfn: The target page frame number
 * @mask: mask of bits that the caller is interested in
 */
void set_pfnblock_flags_mask(struct page *page, unsigned long flags,
                             unsigned long pfn,
                             unsigned long mask)
{
    unsigned long *bitmap;
    unsigned long bitidx, word_bitidx;
    unsigned long old_word, word;

    BUILD_BUG_ON(NR_PAGEBLOCK_BITS != 4);
    BUILD_BUG_ON(MIGRATE_TYPES > (1 << PB_migratetype_bits));

    bitmap = get_pageblock_bitmap(page, pfn);
    bitidx = pfn_to_bitidx(page, pfn);
    word_bitidx = bitidx / BITS_PER_LONG;
    bitidx &= (BITS_PER_LONG-1);

    VM_BUG_ON_PAGE(!zone_spans_pfn(page_zone(page), pfn), page);

    mask <<= bitidx;
    flags <<= bitidx;

    word = READ_ONCE(bitmap[word_bitidx]);
    for (;;) {
        old_word = cmpxchg(&bitmap[word_bitidx], word, (word & ~mask) | flags);
        if (word == old_word)
            break;
        word = old_word;
    }
}

void set_pageblock_migratetype(struct page *page, int migratetype)
{
    set_pfnblock_flags_mask(page, (unsigned long)migratetype,
                            page_to_pfn(page), MIGRATETYPE_MASK);
}

/*
 * Initially all pages are reserved - free ones are freed
 * up by memblock_free_all() once the early boot process is
 * done. Non-atomic initialization, single-pass.
 *
 * All aligned pageblocks are initialized to the specified migratetype
 * (usually MIGRATE_MOVABLE). Besides setting the migratetype, no related
 * zone stats (e.g., nr_isolate_pageblock) are touched.
 */
void __meminit
memmap_init_range(unsigned long size, int nid, unsigned long zone,
                  unsigned long start_pfn, unsigned long zone_end_pfn,
                  enum meminit_context context,
                  struct vmem_altmap *altmap, int migratetype)
{
    struct page *page;
    unsigned long pfn, end_pfn = start_pfn + size;

    if (highest_memmap_pfn < end_pfn - 1)
        highest_memmap_pfn = end_pfn - 1;

    for (pfn = start_pfn; pfn < end_pfn; ) {
        page = pfn_to_page(pfn);
        __init_single_page(page, pfn, zone, nid);
        if (context == MEMINIT_HOTPLUG)
            __SetPageReserved(page);

        /*
         * Usually, we want to mark the pageblock MIGRATE_MOVABLE,
         * such that unmovable allocations won't be scattered all
         * over the place during system boot.
         */
        if (IS_ALIGNED(pfn, pageblock_nr_pages)) {
            set_pageblock_migratetype(page, migratetype);
            cond_resched();
        }
        pfn++;
    }
}

/*
 * Only struct pages that correspond to ranges defined by memblock.memory
 * are zeroed and initialized by going through __init_single_page() during
 * memmap_init_zone_range().
 *
 * But, there could be struct pages that correspond to holes in
 * memblock.memory. This can happen because of the following reasons:
 * - physical memory bank size is not necessarily the exact multiple of the
 *   arbitrary section size
 * - early reserved memory may not be listed in memblock.memory
 * - memory layouts defined with memmap= kernel parameter may not align
 *   nicely with memmap sections
 *
 * Explicitly initialize those struct pages so that:
 * - PG_Reserved is set
 * - zone and node links point to zone and node that span the page if the
 *   hole is in the middle of a zone
 * - zone and node links point to adjacent zone/node if the hole falls on
 *   the zone boundary; the pages in such holes will be prepended to the
 *   zone/node above the hole except for the trailing pages in the last
 *   section that will be appended to the zone/node below.
 */
static void __init init_unavailable_range(unsigned long spfn,
                                          unsigned long epfn,
                                          int zone, int node)
{
    unsigned long pfn;
    u64 pgcnt = 0;

    for (pfn = spfn; pfn < epfn; pfn++) {
        if (!pfn_valid(ALIGN_DOWN(pfn, pageblock_nr_pages))) {
            pfn = ALIGN_DOWN(pfn, pageblock_nr_pages) + pageblock_nr_pages - 1;
            continue;
        }
        __init_single_page(pfn_to_page(pfn), pfn, zone, node);
        __SetPageReserved(pfn_to_page(pfn));
        pgcnt++;
    }

    if (pgcnt)
        pr_info("On node %d, zone %s: %lld pages in unavailable ranges",
                node, zone_names[zone], pgcnt);
}

static void __init
memmap_init_zone_range(struct zone *zone,
                       unsigned long start_pfn,
                       unsigned long end_pfn,
                       unsigned long *hole_pfn)
{
    unsigned long zone_start_pfn = zone->zone_start_pfn;
    unsigned long zone_end_pfn = zone_start_pfn + zone->spanned_pages;
    int nid = zone_to_nid(zone), zone_id = zone_idx(zone);

    start_pfn = clamp(start_pfn, zone_start_pfn, zone_end_pfn);
    end_pfn = clamp(end_pfn, zone_start_pfn, zone_end_pfn);

    if (start_pfn >= end_pfn)
        return;

    memmap_init_range(end_pfn - start_pfn, nid, zone_id, start_pfn,
                      zone_end_pfn, MEMINIT_EARLY, NULL, MIGRATE_MOVABLE);

    if (*hole_pfn < start_pfn)
        init_unavailable_range(*hole_pfn, start_pfn, zone_id, nid);

    *hole_pfn = end_pfn;
}

static void __init memmap_init(void)
{
    unsigned long start_pfn, end_pfn;
    unsigned long hole_pfn = 0;
    int i, j, zone_id = 0, nid;

    for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
        struct pglist_data *node = NODE_DATA(nid);

        for (j = 0; j < MAX_NR_ZONES; j++) {
            struct zone *zone = node->node_zones + j;

            if (!populated_zone(zone))
                continue;

            memmap_init_zone_range(zone, start_pfn, end_pfn, &hole_pfn);
            zone_id = j;
        }
    }

    init_unavailable_range(hole_pfn, end_pfn, zone_id, nid);
}

/*
 * This finds a zone that can be used for ZONE_MOVABLE pages. The
 * assumption is made that zones within a node are ordered in monotonic
 * increasing memory addresses so that the "highest" populated zone is used
 */
static void __init find_usable_zone_for_movable(void)
{
    int zone_index;
    for (zone_index = MAX_NR_ZONES - 1; zone_index >= 0; zone_index--) {
        if (zone_index == ZONE_MOVABLE)
            continue;

        if (arch_zone_highest_possible_pfn[zone_index] >
            arch_zone_lowest_possible_pfn[zone_index])
            break;
    }

    VM_BUG_ON(zone_index == -1);
    movable_zone = zone_index;
}

/*
 * Find the PFN the Movable zone begins in each node. Kernel memory
 * is spread evenly between nodes as long as the nodes have enough
 * memory. When they don't, some nodes will have more kernelcore than
 * others
 */
static void __init find_zone_movable_pfns_for_nodes(void)
{
    /* Need to find movable_zone earlier when movable_node is specified. */
    find_usable_zone_for_movable();
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
    find_zone_movable_pfns_for_nodes();

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
    for_each_node(nid) {
        pg_data_t *pgdat = NODE_DATA(nid);
        free_area_init_node(nid);

        /* Any memory on that node */
        if (pgdat->node_present_pages)
            node_set_state(nid, N_MEMORY);
        check_for_memory(pgdat, nid);
    }

    memmap_init();
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

static void __meminit zone_init_free_lists(struct zone *zone)
{
    unsigned int order, t;
    for_each_migratetype_order(order, t) {
        INIT_LIST_HEAD(&zone->free_area[order].free_list[t]);
        zone->free_area[order].nr_free = 0;
    }
}

void __meminit
init_currently_empty_zone(struct zone *zone,
                          unsigned long zone_start_pfn, unsigned long size)
{
    struct pglist_data *pgdat = zone->zone_pgdat;
    int zone_idx = zone_idx(zone) + 1;

    if (zone_idx > pgdat->nr_zones)
        pgdat->nr_zones = zone_idx;

    zone->zone_start_pfn = zone_start_pfn;

    pr_debug("Initialising map node %d zone %lu pfns %lu -> %lu\n",
             pgdat->node_id,
             (unsigned long)zone_idx(zone),
             zone_start_pfn, (zone_start_pfn + size));

    zone_init_free_lists(zone);
    zone->initialized = 1;
}

static inline bool
prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
                    int preferred_nid, nodemask_t *nodemask,
                    struct alloc_context *ac, gfp_t *alloc_gfp,
                    unsigned int *alloc_flags)
{
    ac->highest_zoneidx = gfp_zone(gfp_mask);
    ac->zonelist = node_zonelist(preferred_nid, gfp_mask);
    ac->nodemask = nodemask;
    ac->migratetype = gfp_migratetype(gfp_mask);

    /* Dirty zone balancing only done in the fast path */
    ac->spread_dirty_pages = (gfp_mask & __GFP_WRITE);

    /*
     * The preferred zone is used for statistics but crucially it is
     * also used as the starting point for the zonelist iterator. It
     * may get reset for allocations that ignore memory policies.
     */
    ac->preferred_zoneref =
        first_zones_zonelist(ac->zonelist, ac->highest_zoneidx, ac->nodemask);

    return true;
}

/*
 * The restriction on ZONE_DMA32 as being a suitable zone to use to avoid
 * fragmentation is subtle. If the preferred zone was HIGHMEM then
 * premature use of a lower zone may cause lowmem pressure problems that
 * are worse than fragmentation. If the next zone is ZONE_DMA then it is
 * probably too small. It only makes sense to spread allocations to avoid
 * fragmentation between the Normal and DMA32 zones.
 */
static inline unsigned int
alloc_flags_nofragment(struct zone *zone, gfp_t gfp_mask)
{
    unsigned int alloc_flags;

    /*
     * __GFP_KSWAPD_RECLAIM is assumed to be the same as ALLOC_KSWAPD
     * to save a branch.
     */
    alloc_flags = (__force int) (gfp_mask & __GFP_KSWAPD_RECLAIM);

    if (!zone)
        return alloc_flags;

    if (zone_idx(zone) != ZONE_NORMAL)
        return alloc_flags;

    /*
     * If ZONE_DMA32 exists, assume it is the one after ZONE_NORMAL and
     * the pointer is within zone->zone_pgdat->node_zones[]. Also assume
     * on UMA that if Normal is populated then so is DMA32.
     */
    BUILD_BUG_ON(ZONE_NORMAL - ZONE_DMA32 != 1);
    if (nr_online_nodes > 1 && !populated_zone(--zone))
        return alloc_flags;

    alloc_flags |= ALLOC_NOFRAGMENT;
    return alloc_flags;
}

static inline bool pcp_allowed_order(unsigned int order)
{
    if (order <= PAGE_ALLOC_COSTLY_ORDER)
        return true;

    return false;
}

static inline bool check_new_pcp(struct page *page)
{
    return false;
}

static inline void
del_page_from_free_list(struct page *page, struct zone *zone,
                        unsigned int order)
{
    list_del(&page->lru);
    __ClearPageBuddy(page);
    set_page_private(page, 0);
    zone->free_area[order].nr_free--;
}

/* Used for pages not on another list */
static inline void
add_to_free_list(struct page *page, struct zone *zone,
                 unsigned int order, int migratetype)
{
    struct free_area *area = &zone->free_area[order];

    list_add(&page->lru, &area->free_list[migratetype]);
    area->nr_free++;
}

/* Used for pages not on another list */
static inline void
add_to_free_list_tail(struct page *page, struct zone *zone,
                      unsigned int order, int migratetype)
{
    struct free_area *area = &zone->free_area[order];

    list_add_tail(&page->lru, &area->free_list[migratetype]);
    area->nr_free++;
}

static inline void
set_buddy_order(struct page *page, unsigned int order)
{
    set_page_private(page, order);
    __SetPageBuddy(page);
}

/*
 * The order of subdivision here is critical for the IO subsystem.
 * Please do not alter this order without good reasons and regression
 * testing. Specifically, as large blocks of memory are subdivided,
 * the order in which smaller blocks are delivered depends on the order
 * they're subdivided in this function. This is the primary factor
 * influencing the order in which pages are delivered to the IO
 * subsystem according to empirical testing, and this is also justified
 * by considering the behavior of a buddy system containing a single
 * large block of memory acted on by a series of small allocations.
 * This behavior is a critical factor in sglist merging's success.
 *
 * -- nyc
 */
static inline void expand(struct zone *zone, struct page *page,
                          int low, int high, int migratetype)
{
    unsigned long size = 1 << high;

    while (high > low) {
        high--;
        size >>= 1;

        add_to_free_list(&page[size], zone, high, migratetype);
        set_buddy_order(&page[size], high);
    }
}

/*
 * Go through the free lists for the given migratetype and remove
 * the smallest available page from the freelists
 */
static __always_inline
struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
                                int migratetype)
{
    struct page *page;
    struct free_area *area;
    unsigned int current_order;

    /* Find a page of the appropriate size in the preferred list */
    for (current_order = order; current_order < MAX_ORDER; ++current_order) {
        area = &(zone->free_area[current_order]);
        page = get_page_from_free_area(area, migratetype);
        if (!page)
            continue;
        del_page_from_free_list(page, zone, current_order);
        expand(zone, page, order, current_order, migratetype);
        set_pcppage_migratetype(page, migratetype);
        return page;
    }

    return NULL;
}

/*
 * When we are falling back to another migratetype during allocation, try to
 * steal extra free pages from the same pageblocks to satisfy further
 * allocations, instead of polluting multiple pageblocks.
 *
 * If we are stealing a relatively large buddy page, it is likely there will
 * be more free pages in the pageblock, so try to steal them all. For
 * reclaimable and unmovable allocations, we steal regardless of page size,
 * as fragmentation caused by those allocations polluting movable pageblocks
 * is worse than movable allocations stealing from unmovable and reclaimable
 * pageblocks.
 */
static bool can_steal_fallback(unsigned int order, int start_mt)
{
    /*
     * Leaving this order check is intended, although there is
     * relaxed order check in next check. The reason is that
     * we can actually steal whole pageblock if this condition met,
     * but, below check doesn't guarantee it and that is just heuristic
     * so could be changed anytime.
     */
    if (order >= pageblock_order)
        return true;

    if (order >= pageblock_order / 2 ||
        start_mt == MIGRATE_RECLAIMABLE ||
        start_mt == MIGRATE_UNMOVABLE ||
        page_group_by_mobility_disabled)
        return true;

    return false;
}

/*
 * Check whether there is a suitable fallback freepage with requested order.
 * If only_stealable is true, this function returns fallback_mt only if
 * we can steal other freepages all together. This would help to reduce
 * fragmentation due to mixed migratetype pages in one pageblock.
 */
int find_suitable_fallback(struct free_area *area, unsigned int order,
                           int migratetype, bool only_stealable,
                           bool *can_steal)
{
    int i;
    int fallback_mt;

    if (area->nr_free == 0)
        return -1;

    *can_steal = false;
    for (i = 0;; i++) {
        fallback_mt = fallbacks[migratetype][i];
        if (fallback_mt == MIGRATE_TYPES)
            break;

        if (free_area_empty(area, fallback_mt))
            continue;

        if (can_steal_fallback(order, migratetype))
            *can_steal = true;

        if (!only_stealable)
            return fallback_mt;

        if (*can_steal)
            return fallback_mt;
    }

    return -1;
}

/*
 * Used for pages which are on another list. Move the pages to the tail
 * of the list - so the moved pages won't immediately be considered for
 * allocation again (e.g., optimization for memory onlining).
 */
static inline void
move_to_free_list(struct page *page, struct zone *zone,
                  unsigned int order, int migratetype)
{
    struct free_area *area = &zone->free_area[order];

    list_move_tail(&page->lru, &area->free_list[migratetype]);
}

static void change_pageblock_range(struct page *pageblock_page,
                                   int start_order, int migratetype)
{
    int nr_pageblocks = 1 << (start_order - pageblock_order);

    while (nr_pageblocks--) {
        set_pageblock_migratetype(pageblock_page, migratetype);
        pageblock_page += pageblock_nr_pages;
    }
}

/*
 * This function implements actual steal behaviour. If order is large enough,
 * we can steal whole pageblock. If not, we first move freepages in this
 * pageblock to our migratetype and determine how many already-allocated pages
 * are there in the pageblock with a compatible migratetype. If at least half
 * of pages are free or compatible, we can change migratetype of the pageblock
 * itself, so pages freed in the future will be put on the correct free list.
 */
static void
steal_suitable_fallback(struct zone *zone, struct page *page,
                        unsigned int alloc_flags, int start_type,
                        bool whole_block)
{
    int old_block_type;
    unsigned int current_order = buddy_order(page);

    old_block_type = get_pageblock_migratetype(page);

    /*
     * This can happen due to races and we want to prevent broken
     * highatomic accounting.
     */
    if (is_migrate_highatomic(old_block_type))
        goto single_page;

    /* Take ownership for orders >= pageblock_order */
    if (current_order >= pageblock_order) {
        change_pageblock_range(page, current_order, start_type);
        goto single_page;
    }

    panic("%s: order(%d) END\n", __func__, current_order);

single_page:
    move_to_free_list(page, zone, current_order, start_type);
}

/*
 * Try finding a free buddy page on the fallback list and put it on the free
 * list of requested migratetype, possibly along with other pages from the same
 * block, depending on fragmentation avoidance heuristics. Returns true if
 * fallback was found so that __rmqueue_smallest() can grab it.
 *
 * The use of signed ints for order and current_order is a deliberate
 * deviation from the rest of this file, to make the for loop
 * condition simpler.
 */
static __always_inline bool
__rmqueue_fallback(struct zone *zone, int order,
                   int start_migratetype, unsigned int alloc_flags)
{
    bool can_steal;
    int fallback_mt;
    int current_order;
    struct page *page;
    struct free_area *area;
    int min_order = order;

    /*
     * Do not steal pages from freelists belonging to other pageblocks
     * i.e. orders < pageblock_order. If there are no local zones free,
     * the zonelists will be reiterated without ALLOC_NOFRAGMENT.
     */
    if (alloc_flags & ALLOC_NOFRAGMENT)
        min_order = pageblock_order;

    /*
     * Find the largest available free page in the other list. This roughly
     * approximates finding the pageblock with the most free pages, which
     * would be too costly to do exactly.
     */
    for (current_order = MAX_ORDER - 1;
         current_order >= min_order; --current_order) {

        area = &(zone->free_area[current_order]);
        fallback_mt = find_suitable_fallback(area, current_order,
                                             start_migratetype, false,
                                             &can_steal);
        if (fallback_mt == -1)
            continue;

        /*
         * We cannot steal all free pages from the pageblock and the
         * requested migratetype is movable. In that case it's better to
         * steal and split the smallest available page instead of the
         * largest available page, because even if the next movable
         * allocation falls back into a different pageblock than this
         * one, it won't cause permanent fragmentation.
         */
        if (!can_steal && start_migratetype == MIGRATE_MOVABLE &&
            current_order > order)
            goto find_smallest;

        goto do_steal;
    }

    return false;

 find_smallest:
    panic("%s: NO implementation!\n", __func__);

 do_steal:
    page = get_page_from_free_area(area, fallback_mt);

    steal_suitable_fallback(zone, page, alloc_flags,
                            start_migratetype, can_steal);

    return true;
}

/*
 * Do the hard work of removing an element from the buddy allocator.
 * Call me with the zone->lock already held.
 */
static __always_inline struct page *
__rmqueue(struct zone *zone, unsigned int order,
          int migratetype, unsigned int alloc_flags)
{
    struct page *page;

retry:
    page = __rmqueue_smallest(zone, order, migratetype);
    if (unlikely(!page)) {
        if (!page && __rmqueue_fallback(zone, order, migratetype, alloc_flags))
            goto retry;
    }

    return page;
}

static const char *page_bad_reason(struct page *page, unsigned long flags)
{
    const char *bad_reason = NULL;

    if (unlikely(atomic_read(&page->_mapcount) != -1))
        bad_reason = "nonzero mapcount";
    if (unlikely(page->mapping != NULL))
        bad_reason = "non-NULL mapping";
    if (unlikely(page_ref_count(page) != 0))
        bad_reason = "nonzero _refcount";
    if (unlikely(page->flags & flags)) {
        if (flags == PAGE_FLAGS_CHECK_AT_PREP)
            bad_reason = "PAGE_FLAGS_CHECK_AT_PREP flag(s) set";
        else
            bad_reason = "PAGE_FLAGS_CHECK_AT_FREE flag(s) set";
    }
    return bad_reason;
}

static void bad_page(struct page *page, const char *reason)
{
#if 0
    static unsigned long resume;
    static unsigned long nr_shown;
    static unsigned long nr_unshown;
#endif

    /*
     * Allow a burst of 60 reports, then keep quiet for that minute;
     * or allow a steady drip of one report per second.
     */
#if 0
    if (nr_shown == 60) {
        if (time_before(jiffies, resume)) {
            nr_unshown++;
            goto out;
        }
        if (nr_unshown) {
            pr_alert("BUG: Bad page state: %lu messages suppressed\n",
                     nr_unshown);
            nr_unshown = 0;
        }
        nr_shown = 0;
    }
    if (nr_shown++ == 0)
        resume = jiffies + 60 * HZ;
#endif

    pr_alert("BUG: Bad page state in process %s  pfn:%05lx\n",
             current->comm, page_to_pfn(page));
#if 0
    dump_page(page, reason);

    print_modules();
    dump_stack();
#endif

//out:
    /* Leave bad fields for debug, except PageBuddy could make trouble */
    page_mapcount_reset(page); /* remove PageBuddy */
}

static void check_new_page_bad(struct page *page)
{
    if (unlikely(page->flags & __PG_HWPOISON)) {
        /* Don't complain about hwpoisoned pages */
        page_mapcount_reset(page); /* remove PageBuddy */
        return;
    }

    bad_page(page, page_bad_reason(page, PAGE_FLAGS_CHECK_AT_PREP));
}

/*
 * A bad page could be due to a number of fields. Instead of multiple branches,
 * try and check multiple fields with one check. The caller must do a detailed
 * check if necessary.
 */
static inline bool
page_expected_state(struct page *page, unsigned long check_flags)
{
    if (unlikely(atomic_read(&page->_mapcount) != -1))
        return false;

    if (unlikely((unsigned long)page->mapping | page_ref_count(page) |
                 (page->flags & check_flags)))
        return false;

    return true;
}

/*
 * This page is about to be returned from the page allocator
 */
static inline int check_new_page(struct page *page)
{
    if (likely(page_expected_state(page,
                                   PAGE_FLAGS_CHECK_AT_PREP|__PG_HWPOISON)))
        return 0;

    check_new_page_bad(page);
    return 1;
}

/*
 * With DEBUG_VM disabled, free order-0 pages are checked for expected state
 * when pcp lists are being refilled from the free lists. With debug_pagealloc
 * enabled, they are also checked when being allocated from the pcp lists.
 */
static inline bool check_pcp_refill(struct page *page)
{
    return check_new_page(page);
}

/*
 * Obtain a specified number of elements from the buddy allocator, all under
 * a single hold of the lock, for efficiency.  Add them to the supplied list.
 * Returns the number of new pages which were placed at *list.
 */
static int
rmqueue_bulk(struct zone *zone, unsigned int order,
             unsigned long count, struct list_head *list,
             int migratetype, unsigned int alloc_flags)
{
    int i, allocated = 0;

    /*
     * local_lock_irq held so equivalent to spin_lock_irqsave for
     * both PREEMPT_RT and non-PREEMPT_RT configurations.
     */
    spin_lock(&zone->lock);
    for (i = 0; i < count; ++i) {
        struct page *page = __rmqueue(zone, order, migratetype, alloc_flags);
        if (unlikely(page == NULL))
            break;

        if (unlikely(check_pcp_refill(page)))
            continue;

        /*
         * Split buddy pages returned by expand() are received here in
         * physical page order. The page is added to the tail of
         * caller's list. From the callers perspective, the linked list
         * is ordered by page number under some conditions. This is
         * useful for IO devices that can forward direction from the
         * head, thus also in the physical page order. This is useful
         * for IO devices that can merge IO requests if the physical
         * pages are ordered properly.
         */
        list_add_tail(&page->lru, list);
        allocated++;
    }

    /*
     * i pages were removed from the buddy list even if some leak due
     * to check_pcp_refill failing so adjust NR_FREE_PAGES based
     * on i. Do not confuse with 'allocated' which is the number of
     * pages added to the pcp list.
     */
    __mod_zone_page_state(zone, NR_FREE_PAGES, -(i << order));
    spin_unlock(&zone->lock);
    return allocated;
}

/* Lock and remove page from the per-cpu list */
/* Remove page from the per-cpu list, caller must protect the list */
static inline
struct page *
__rmqueue_pcplist(struct zone *zone, unsigned int order,
                  int migratetype, unsigned int alloc_flags,
                  struct per_cpu_pages *pcp, struct list_head *list)
{
    struct page *page;

    do {
        if (list_empty(list)) {
            int alloced;
            int batch = READ_ONCE(pcp->batch);

            /*
             * Scale batch relative to order if batch implies
             * free pages can be stored on the PCP. Batch can
             * be 1 for small zones or for boot pagesets which
             * should never store free pages as the pages may
             * belong to arbitrary zones.
             */
            if (batch > 1)
                batch = max(batch >> order, 2);

            alloced = rmqueue_bulk(zone, order, batch, list,
                                   migratetype, alloc_flags);

            pcp->count += alloced << order;
            if (unlikely(list_empty(list)))
                return NULL;
        }

        page = list_first_entry(list, struct page, lru);
        list_del(&page->lru);
        pcp->count -= 1 << order;
    } while (check_new_pcp(page));

    return page;
}

static struct page *
rmqueue_pcplist(struct zone *preferred_zone,
                struct zone *zone, unsigned int order,
                gfp_t gfp_flags, int migratetype,
                unsigned int alloc_flags)
{
    struct per_cpu_pages *pcp;
    struct list_head *list;
    struct page *page;
    unsigned long flags;

    local_lock_irqsave(&pagesets.lock, flags);

    /*
     * On allocation, reduce the number of pages that are batch freed.
     * See nr_pcp_free() where free_factor is increased for subsequent
     * frees.
     */
    pcp = this_cpu_ptr(zone->per_cpu_pageset);
    pcp->free_factor >>= 1;
    list = &pcp->lists[order_to_pindex(migratetype, order)];
    page = __rmqueue_pcplist(zone, order, migratetype, alloc_flags, pcp, list);
    local_unlock_irqrestore(&pagesets.lock, flags);
#if 0
    if (page) {
        __count_zid_vm_events(PGALLOC, page_zonenum(page), 1);
    }
#endif
    return page;
}

static bool check_new_pages(struct page *page, unsigned int order)
{
    int i;
    for (i = 0; i < (1 << order); i++) {
        struct page *p = page + i;

        if (unlikely(check_new_page(p)))
            return true;
    }

    return false;
}

/*
 * Allocate a page from the given zone. Use pcplists for order-0 allocations.
 */
static inline
struct page *rmqueue(struct zone *preferred_zone, struct zone *zone,
                     unsigned int order, gfp_t gfp_flags,
                     unsigned int alloc_flags, int migratetype)
{
    struct page *page;
    unsigned long flags;

    if (likely(pcp_allowed_order(order))) {
        page = rmqueue_pcplist(preferred_zone, zone, order,
                               gfp_flags, migratetype, alloc_flags);
        goto out;
    }

    /*
     * We most definitely don't want callers attempting to
     * allocate greater than order-1 page units with __GFP_NOFAIL.
     */
    WARN_ON_ONCE((gfp_flags & __GFP_NOFAIL) && (order > 1));
    spin_lock_irqsave(&zone->lock, flags);

    do {
        page = NULL;
        /*
         * order-0 request can reach here when the pcplist is skipped
         * due to non-CMA allocation context. HIGHATOMIC area is
         * reserved for high-order atomic allocation, so order-0
         * request should skip it.
         */
        if (order > 0 && alloc_flags & ALLOC_HARDER)
            page = __rmqueue_smallest(zone, order, MIGRATE_HIGHATOMIC);
        if (!page)
            page = __rmqueue(zone, order, migratetype, alloc_flags);
    } while (page && check_new_pages(page, order));
    if (!page)
        goto failed;

    spin_unlock_irqrestore(&zone->lock, flags);

    panic("%s: END!\n", __func__);

 out:
    /* Separate test+clear to avoid unnecessary atomics */
#if 0
    if (test_bit(ZONE_BOOSTED_WATERMARK, &zone->flags)) {
        clear_bit(ZONE_BOOSTED_WATERMARK, &zone->flags);
        wakeup_kswapd(zone, 0, 0, zone_idx(zone));
    }
#endif

    return page;

 failed:
    spin_unlock_irqrestore(&zone->lock, flags);
    return NULL;
}

static void
kernel_init_free_pages(struct page *page, int numpages, bool zero_tags)
{
    int i;

    for (i = 0; i < numpages; i++)
        clear_highpage(page + i);
}

inline void
post_alloc_hook(struct page *page, unsigned int order, gfp_t gfp_flags)
{
    set_page_private(page, 0);
    set_page_refcounted(page);

    if (want_init_on_alloc(gfp_flags))
        kernel_init_free_pages(page, 1 << order, gfp_flags & __GFP_ZEROTAGS);
}

void prep_compound_page(struct page *page, unsigned int order)
{
    int i;
    int nr_pages = 1 << order;

    __SetPageHead(page);
    for (i = 1; i < nr_pages; i++) {
        struct page *p = page + i;
        p->mapping = TAIL_MAPPING;
        set_compound_head(p, page);
    }

    set_compound_page_dtor(page, COMPOUND_PAGE_DTOR);
    set_compound_order(page, order);
    atomic_set(compound_mapcount_ptr(page), -1);
    if (hpage_pincount_available(page))
        atomic_set(compound_pincount_ptr(page), 0);
}

static void
prep_new_page(struct page *page, unsigned int order,
              gfp_t gfp_flags, unsigned int alloc_flags)
{
    post_alloc_hook(page, order, gfp_flags);

    if (order && (gfp_flags & __GFP_COMP))
        prep_compound_page(page, order);

    /*
     * page is set pfmemalloc when ALLOC_NO_WATERMARKS was necessary to
     * allocate the page. The expectation is that the caller is taking
     * steps that will free more memory. The caller should avoid the page
     * being used for !PFMEMALLOC purposes.
     */
    if (alloc_flags & ALLOC_NO_WATERMARKS)
        set_page_pfmemalloc(page);
    else
        clear_page_pfmemalloc(page);
}

/*
 * Move the free pages in a range to the freelist tail of the requested type.
 * Note that start_page and end_pages are not aligned on a pageblock
 * boundary. If alignment is required, use move_freepages_block()
 */
static int move_freepages(struct zone *zone,
                          unsigned long start_pfn, unsigned long end_pfn,
                          int migratetype, int *num_movable)
{
    struct page *page;
    unsigned long pfn;
    unsigned int order;
    int pages_moved = 0;

    for (pfn = start_pfn; pfn <= end_pfn;) {
        page = pfn_to_page(pfn);
        if (!PageBuddy(page)) {
            /*
             * We assume that pages that could be isolated for
             * migration are movable. But we don't actually try
             * isolating, as that would be expensive.
             */
            if (num_movable && (PageLRU(page) || __PageMovable(page)))
                (*num_movable)++;
            pfn++;
            continue;
        }

        /* Make sure we are not inadvertently changing nodes */
        VM_BUG_ON_PAGE(page_to_nid(page) != zone_to_nid(zone), page);
        VM_BUG_ON_PAGE(page_zone(page) != zone, page);

        order = buddy_order(page);
        move_to_free_list(page, zone, order, migratetype);
        pfn += 1 << order;
        pages_moved += 1 << order;
    }

    return pages_moved;
}

int move_freepages_block(struct zone *zone, struct page *page,
                         int migratetype, int *num_movable)
{
    unsigned long start_pfn, end_pfn, pfn;

    if (num_movable)
        *num_movable = 0;

    pfn = page_to_pfn(page);
    start_pfn = pfn & ~(pageblock_nr_pages - 1);
    end_pfn = start_pfn + pageblock_nr_pages - 1;

    /* Do not cross zone boundaries */
    if (!zone_spans_pfn(zone, start_pfn))
        start_pfn = pfn;
    if (!zone_spans_pfn(zone, end_pfn))
        return 0;

    return move_freepages(zone, start_pfn, end_pfn, migratetype, num_movable);
}

/*
 * Reserve a pageblock for exclusive use of high-order atomic allocations if
 * there are no empty page blocks that contain a page with a suitable order
 */
static void
reserve_highatomic_pageblock(struct page *page,
                             struct zone *zone, unsigned int alloc_order)
{
    int mt;
    unsigned long max_managed, flags;

    /*
     * Limit the number reserved to 1 pageblock or roughly 1% of a zone.
     * Check is race-prone but harmless.
     */
    max_managed = (zone_managed_pages(zone) / 100) + pageblock_nr_pages;
    if (zone->nr_reserved_highatomic >= max_managed)
        return;

    spin_lock_irqsave(&zone->lock, flags);

    /* Recheck the nr_reserved_highatomic limit under the lock */
    if (zone->nr_reserved_highatomic >= max_managed)
        goto out_unlock;

    /* Yoink! */
    mt = get_pageblock_migratetype(page);
    if (!is_migrate_highatomic(mt)) {
        zone->nr_reserved_highatomic += pageblock_nr_pages;
        set_pageblock_migratetype(page, MIGRATE_HIGHATOMIC);
        move_freepages_block(zone, page, MIGRATE_HIGHATOMIC, NULL);
    }

out_unlock:
    spin_unlock_irqrestore(&zone->lock, flags);
}

/*
 * get_page_from_freelist goes through the zonelist trying to allocate
 * a page.
 */
static struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order,
                       int alloc_flags, const struct alloc_context *ac)
{
    bool no_fallback;
    struct zoneref *z;
    struct zone *zone;
    struct pglist_data *last_pgdat_dirty_limit = NULL;

retry:
    /*
     * Scan zonelist, looking for a zone with enough free.
     * See also __cpuset_node_allowed() comment in kernel/cpuset.c.
     */
    no_fallback = alloc_flags & ALLOC_NOFRAGMENT;
    z = ac->preferred_zoneref;

    for_next_zone_zonelist_nodemask(zone, z, ac->highest_zoneidx,
                                    ac->nodemask) {
        struct page *page;
        //unsigned long mark;

        /*
         * When allocating a page cache page for writing, we
         * want to get it from a node that is within its dirty
         * limit, such that no single node holds more than its
         * proportional share of globally allowed dirty pages.
         * The dirty limits take into account the node's
         * lowmem reserves and high watermark so that kswapd
         * should be able to balance it without having to
         * write pages from its LRU list.
         *
         * XXX: For now, allow allocations to potentially
         * exceed the per-node dirty limit in the slowpath
         * (spread_dirty_pages unset) before going into reclaim,
         * which is important when on a NUMA setup the allowed
         * nodes are together not big enough to reach the
         * global limit.  The proper fix for these situations
         * will require awareness of nodes in the
         * dirty-throttling and the flusher threads.
         */
        if (ac->spread_dirty_pages) {
            if (last_pgdat_dirty_limit == zone->zone_pgdat)
                continue;

            if (!node_dirty_ok(zone->zone_pgdat)) {
                last_pgdat_dirty_limit = zone->zone_pgdat;
                continue;
            }
        }

#if 0
        mark = wmark_pages(zone, alloc_flags & ALLOC_WMARK_MASK);
        if (!zone_watermark_fast(zone, order, mark, ac->highest_zoneidx,
                                 alloc_flags, gfp_mask)) {
        }
#endif

        page = rmqueue(ac->preferred_zoneref->zone, zone, order,
                       gfp_mask, alloc_flags, ac->migratetype);
        if (page) {
            prep_new_page(page, order, gfp_mask, alloc_flags);

            /*
             * If this is a high-order atomic allocation then check
             * if the pageblock should be reserved for the future
             */
            if (unlikely(order && (alloc_flags & ALLOC_HARDER)))
                reserve_highatomic_pageblock(page, zone, order);

            return page;
        }
    }

    /*
     * It's possible on a UMA machine to get through all zones that are
     * fragmented. If avoiding fragmentation, reset and try again.
     */
    if (no_fallback) {
        alloc_flags &= ~ALLOC_NOFRAGMENT;
        goto retry;
    }

    return NULL;
}

/*
 * This is the 'heart' of the zoned buddy allocator.
 */
struct page *
__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
              nodemask_t *nodemask)
{
    struct page *page;
    gfp_t alloc_gfp; /* The gfp_t that was actually used for allocation */
    struct alloc_context ac = { };
    unsigned int alloc_flags = ALLOC_WMARK_LOW;

    /*
     * There are several places where we assume that the order value is sane
     * so bail out early if the request is out of bound.
     */
    if (unlikely(order >= MAX_ORDER)) {
        WARN_ON_ONCE(!(gfp & __GFP_NOWARN));
        return NULL;
    }

    gfp &= gfp_allowed_mask;

    /*
     * Apply scoped allocation constraints. This is mainly about GFP_NOFS
     * resp. GFP_NOIO which has to be inherited for all allocation requests
     * from a particular context which has been marked by
     * memalloc_no{fs,io}_{save,restore}. And PF_MEMALLOC_PIN which ensures
     * movable zones are not used during allocation.
     */
    gfp = current_gfp_context(gfp);
    alloc_gfp = gfp;
    if (!prepare_alloc_pages(gfp, order, preferred_nid, nodemask, &ac,
                             &alloc_gfp, &alloc_flags))
        return NULL;

    /*
     * Forbid the first pass from falling back to types that fragment
     * memory until all local zones are considered.
     */
    alloc_flags |= alloc_flags_nofragment(ac.preferred_zoneref->zone, gfp);

    /* First allocation attempt */
    page = get_page_from_freelist(alloc_gfp, order, alloc_flags, &ac);
    if (likely(page))
        goto out;

    printk("%s: step2\n", __func__);
    alloc_gfp = gfp;
    ac.spread_dirty_pages = false;

    /*
     * Restore the original nodemask if it was potentially replaced with
     * &cpuset_current_mems_allowed to optimize the fast-path attempt.
     */
    ac.nodemask = nodemask;

    //page = __alloc_pages_slowpath(alloc_gfp, order, &ac);

    panic("%s: gfp(%x) order(%d) nid(%d) END\n",
          __func__, gfp, order, preferred_nid);

 out:
    return page;
}
EXPORT_SYMBOL(__alloc_pages);

static void zoneref_set_zone(struct zone *zone, struct zoneref *zoneref)
{
    zoneref->zone = zone;
    zoneref->zone_idx = zone_idx(zone);
}

/*
 * Builds allocation fallback zone lists.
 *
 * Add all populated zones of a node to the zonelist.
 */
static int build_zonerefs_node(pg_data_t *pgdat, struct zoneref *zonerefs)
{
    struct zone *zone;
    int nr_zones = 0;
    enum zone_type zone_type = MAX_NR_ZONES;

    do {
        zone_type--;
        zone = pgdat->node_zones + zone_type;
        if (populated_zone(zone)) {
            zoneref_set_zone(zone, &zonerefs[nr_zones++]);
        }
    } while (zone_type);

    return nr_zones;
}

/*
 * Build zonelists ordered by zone and nodes within zones.
 * This results in conserving DMA zone[s] until all Normal memory is
 * exhausted, but results in overflowing to remote node while memory
 * may still exist in local DMA zone.
 */

static void build_zonelists(pg_data_t *pgdat)
{
    int nr_zones;
    int node, local_node;
    struct zoneref *zonerefs;

    local_node = pgdat->node_id;

    zonerefs = pgdat->node_zonelists[ZONELIST_FALLBACK]._zonerefs;
    nr_zones = build_zonerefs_node(pgdat, zonerefs);
    zonerefs += nr_zones;

    /*
     * Now we build the zonelist so that it contains the zones
     * of all the other nodes.
     * We don't want to pressure a particular node, so when
     * building the zones for node N, we make sure that the
     * zones coming right after the local ones are those from
     * node N+1 (modulo N)
     */
    for (node = local_node + 1; node < MAX_NUMNODES; node++) {
        if (!node_online(node))
            continue;
        nr_zones = build_zonerefs_node(NODE_DATA(node), zonerefs);
        zonerefs += nr_zones;
    }
    for (node = 0; node < local_node; node++) {
        if (!node_online(node))
            continue;
        nr_zones = build_zonerefs_node(NODE_DATA(node), zonerefs);
        zonerefs += nr_zones;
    }

    zonerefs->zone = NULL;
    zonerefs->zone_idx = 0;
}

static void __build_all_zonelists(void *data)
{
    int nid;
    int __maybe_unused cpu;
    pg_data_t *self = data;
    static DEFINE_SPINLOCK(lock);

    spin_lock(&lock);

    /*
     * This node is hotadded and no memory is yet present.   So just
     * building zonelists is fine - no need to touch other nodes.
     */
    if (self && !node_online(self->node_id)) {
        build_zonelists(self);
    } else {
        /*
         * All possible nodes have pgdat preallocated
         * in free_area_init
         */
        for_each_online_node(nid) {
            pg_data_t *pgdat = NODE_DATA(nid);

            build_zonelists(pgdat);
        }
    }

    spin_unlock(&lock);
}

static void
per_cpu_pages_init(struct per_cpu_pages *pcp, struct per_cpu_zonestat *pzstats)
{
    int pindex;

    memset(pcp, 0, sizeof(*pcp));
    memset(pzstats, 0, sizeof(*pzstats));

    for (pindex = 0; pindex < NR_PCP_LISTS; pindex++)
        INIT_LIST_HEAD(&pcp->lists[pindex]);

    /*
     * Set batch and high values safe for a boot pageset. A true percpu
     * pageset's initialization will update them subsequently. Here we don't
     * need to be as careful as pageset_update() as nobody can access the
     * pageset yet.
     */
    pcp->high = BOOT_PAGESET_HIGH;
    pcp->batch = BOOT_PAGESET_BATCH;
    pcp->free_factor = 0;
}

static noinline void __init
build_all_zonelists_init(void)
{
    int cpu;

    __build_all_zonelists(NULL);

    /*
     * Initialize the boot_pagesets that are going to be used
     * for bootstrapping processors. The real pagesets for
     * each zone will be allocated later when the per cpu
     * allocator is available.
     *
     * boot_pagesets are used also for bootstrapping offline
     * cpus if the system is already booted because the pagesets
     * are needed to initialize allocators on a specific cpu too.
     * F.e. the percpu allocator needs the page allocator which
     * needs the percpu allocator in order to allocate its pagesets
     * (a chicken-egg dilemma).
     */
    for_each_possible_cpu(cpu)
        per_cpu_pages_init(&per_cpu(boot_pageset, cpu),
                           &per_cpu(boot_zonestats, cpu));
}

/**
 * nr_free_zone_pages - count number of pages beyond high watermark
 * @offset: The zone index of the highest zone
 *
 * nr_free_zone_pages() counts the number of pages which are beyond the
 * high watermark within all zones at or below a given zone index.  For each
 * zone, the number of pages is calculated as:
 *
 *     nr_free_zone_pages = managed_pages - high_pages
 *
 * Return: number of pages beyond high watermark.
 */
static unsigned long nr_free_zone_pages(int offset)
{
    struct zoneref *z;
    struct zone *zone;

    /* Just pick one node, since fallback list is circular */
    unsigned long sum = 0;

    struct zonelist *zonelist = node_zonelist(numa_node_id(), GFP_KERNEL);

    for_each_zone_zonelist(zone, z, zonelist, offset) {
        unsigned long size = zone_managed_pages(zone);
        unsigned long high = high_wmark_pages(zone);
        if (size > high)
            sum += size - high;
    }

    return sum;
}

/*
 * unless system_state == SYSTEM_BOOTING.
 *
 * __ref due to call of __init annotated helper build_all_zonelists_init
 * [protected by SYSTEM_BOOTING].
 */
void __ref build_all_zonelists(pg_data_t *pgdat)
{
    unsigned long vm_total_pages;

    if (system_state == SYSTEM_BOOTING) {
        build_all_zonelists_init();
    } else {
        __build_all_zonelists(pgdat);
        /* cpuset refresh routine should be here */
    }
    /* Get the number of free pages beyond high watermark in all zones. */
    vm_total_pages = nr_free_zone_pages(gfp_zone(GFP_HIGHUSER_MOVABLE));
    /*
     * Disable grouping by mobility if the number of pages in the
     * system is too low to allow the mechanism to work. It would be
     * more accurate, but expensive to check per-zone. This check is
     * made on memory-hotadd so a system can start with mobility
     * disabled and enable it later
     */
    if (vm_total_pages < (pageblock_nr_pages * MIGRATE_TYPES))
        page_group_by_mobility_disabled = 1;
    else
        page_group_by_mobility_disabled = 0;

    pr_info("Built %u zonelists, mobility grouping %s.  Total pages: %ld\n",
            nr_online_nodes,
            page_group_by_mobility_disabled ? "off" : "on",
            vm_total_pages);
}

/*
 * Initialised pages do not have PageReserved set. This function is
 * called for each range allocated by the bootmem allocator and
 * marks the pages PageReserved. The remaining valid pages are later
 * sent to the buddy page allocator.
 */
void __meminit reserve_bootmem_region(phys_addr_t start, phys_addr_t end)
{
    unsigned long start_pfn = PFN_DOWN(start);
    unsigned long end_pfn = PFN_UP(end);

    for (; start_pfn < end_pfn; start_pfn++) {
        if (pfn_valid(start_pfn)) {
            struct page *page = pfn_to_page(start_pfn);

            /* Avoid false-positive PageTail() */
            INIT_LIST_HEAD(&page->lru);

            /*
             * no need for atomic set_bit because the struct
             * page is not visible yet so nobody should
             * access it yet.
             */
            __SetPageReserved(page);
        }
    }
}

static __always_inline
unsigned long
__get_pfnblock_flags_mask(const struct page *page, unsigned long pfn,
                          unsigned long mask)
{
    unsigned long word;
    unsigned long *bitmap;
    unsigned long bitidx, word_bitidx;

    bitmap = get_pageblock_bitmap(page, pfn);
    bitidx = pfn_to_bitidx(page, pfn);
    word_bitidx = bitidx / BITS_PER_LONG;
    bitidx &= (BITS_PER_LONG-1);

    word = bitmap[word_bitidx];
    return (word >> bitidx) & mask;
}

static __always_inline int
get_pfnblock_migratetype(const struct page *page, unsigned long pfn)
{
    return __get_pfnblock_flags_mask(page, pfn, MIGRATETYPE_MASK);
}

static __always_inline bool
free_pages_prepare(struct page *page, unsigned int order,
                   bool check_free, fpi_t fpi_flags)
{
     VM_BUG_ON_PAGE(PageTail(page), page);
     return true;
}

/*
 * This function checks whether a page is free && is the buddy
 * we can coalesce a page and its buddy if
 * (a) the buddy is not in a hole (check before calling!) &&
 * (b) the buddy is in the buddy system &&
 * (c) a page and its buddy have the same order &&
 * (d) a page and its buddy are in the same zone.
 *
 * For recording whether a page is in the buddy system, we set PageBuddy.
 * Setting, clearing, and testing PageBuddy is serialized by zone->lock.
 *
 * For recording page's order, we use page_private(page).
 */
static inline bool
page_is_buddy(struct page *page, struct page *buddy, unsigned int order)
{
    if (!PageBuddy(buddy))
        return false;

    if (buddy_order(buddy) != order)
        return false;

    /*
     * zone check is done late to avoid uselessly calculating
     * zone/node ids for pages that could never merge.
     */
    if (page_zone_id(page) != page_zone_id(buddy))
        return false;

    VM_BUG_ON_PAGE(page_count(buddy) != 0, buddy);

    return true;
}

/*
 * If this is not the largest possible page, check if the buddy
 * of the next-highest order is free. If it is, it's possible
 * that pages are being freed that will coalesce soon. In case,
 * that is happening, add the free page to the tail of the list
 * so it's less likely to be used soon and more likely to be merged
 * as a higher order page
 */
static inline bool
buddy_merge_likely(unsigned long pfn, unsigned long buddy_pfn,
                   struct page *page, unsigned int order)
{
    struct page *higher_page, *higher_buddy;
    unsigned long combined_pfn;

    if (order >= MAX_ORDER - 2)
        return false;

    combined_pfn = buddy_pfn & pfn;
    higher_page = page + (combined_pfn - pfn);
    buddy_pfn = __find_buddy_pfn(combined_pfn, order + 1);
    higher_buddy = higher_page + (buddy_pfn - combined_pfn);

    return page_is_buddy(higher_page, higher_buddy, order + 1);
}

static inline void
__free_one_page(struct page *page, unsigned long pfn,
                struct zone *zone, unsigned int order,
                int migratetype, fpi_t fpi_flags)
{
    bool to_tail;
    struct page *buddy;
    unsigned long buddy_pfn;
    unsigned long combined_pfn;
    unsigned int max_order;

    max_order = min_t(unsigned int, MAX_ORDER - 1, pageblock_order);

    VM_BUG_ON(!zone_is_initialized(zone));
    //VM_BUG_ON_PAGE(page->flags & PAGE_FLAGS_CHECK_AT_PREP, page);

    VM_BUG_ON(migratetype == -1);
#if 0
    if (likely(!is_migrate_isolate(migratetype)))
        __mod_zone_freepage_state(zone, 1 << order, migratetype);
#endif

    VM_BUG_ON_PAGE(pfn & ((1 << order) - 1), page);

 continue_merging:
    while (order < max_order) {
        buddy_pfn = __find_buddy_pfn(pfn, order);
        buddy = page + (buddy_pfn - pfn);

        if (!page_is_buddy(page, buddy, order))
            goto done_merging;

        del_page_from_free_list(buddy, zone, order);
        combined_pfn = buddy_pfn & pfn;
        page = page + (combined_pfn - pfn);
        pfn = combined_pfn;
        order++;
    }
    if (order < MAX_ORDER - 1) {
        /* If we are here, it means order is >= pageblock_order.
         * We want to prevent merge between freepages on isolate
         * pageblock and normal pageblock. Without this, pageblock
         * isolation could cause incorrect freepage or CMA accounting.
         *
         * We don't want to hit this code for the more frequent
         * low-order merging.
         */

        buddy_pfn = __find_buddy_pfn(pfn, order);
        buddy = page + (buddy_pfn - pfn);

        max_order = order + 1;
        goto continue_merging;
    }

 done_merging:
    set_buddy_order(page, order);

    if (fpi_flags & FPI_TO_TAIL)
        to_tail = true;
    else
        to_tail = buddy_merge_likely(pfn, buddy_pfn, page, order);

    if (to_tail)
        add_to_free_list_tail(page, zone, order, migratetype);
    else
        add_to_free_list(page, zone, order, migratetype);
}

static void
__free_pages_ok(struct page *page, unsigned int order, fpi_t fpi_flags)
{
    int migratetype;
    unsigned long flags;
    unsigned long pfn = page_to_pfn(page);
    struct zone *zone = page_zone(page);

    if (!free_pages_prepare(page, order, true, fpi_flags))
        return;

    migratetype = get_pfnblock_migratetype(page, pfn);

    spin_lock_irqsave(&zone->lock, flags);
    __free_one_page(page, pfn, zone, order, migratetype, fpi_flags);
    spin_unlock_irqrestore(&zone->lock, flags);

    //__count_vm_events(PGFREE, 1 << order);
}

void __free_pages_core(struct page *page, unsigned int order)
{
    unsigned int loop;
    struct page *p = page;
    unsigned int nr_pages = 1 << order;

    /*
     * When initializing the memmap, __init_single_page() sets the refcount
     * of all pages to 1 ("allocated"/"not free"). We have to set the
     * refcount of all involved pages to 0.
     */
    prefetchw(p);
    for (loop = 0; loop < (nr_pages - 1); loop++, p++) {
        prefetchw(p + 1);
        __ClearPageReserved(p);
        set_page_count(p, 0);
    }
    __ClearPageReserved(p);
    set_page_count(p, 0);

    atomic_long_add(nr_pages, &page_zone(page)->managed_pages);

    /*
     * Bypass PCP and place fresh pages right to the tail, primarily
     * relevant for memory onlining.
     */
    __free_pages_ok(page, order, FPI_TO_TAIL | FPI_SKIP_KASAN_POISON);
}

void __init
memblock_free_pages(struct page *page, unsigned long pfn,
                    unsigned int order)
{
    __free_pages_core(page, order);
}

/*
 * Calculate and set new high and batch values for all per-cpu pagesets of a
 * zone based on the zone's size.
 */
static void zone_set_pageset_high_and_batch(struct zone *zone, int cpu_online)
{
#if 0
    int new_high, new_batch;

    new_batch = max(1, zone_batchsize(zone));
    new_high = zone_highsize(zone, new_batch, cpu_online);

    if (zone->pageset_high == new_high &&
        zone->pageset_batch == new_batch)
        return;

    zone->pageset_high = new_high;
    zone->pageset_batch = new_batch;

    __zone_set_pageset_high_and_batch(zone, new_high, new_batch);
#endif
}

void __meminit setup_zone_pageset(struct zone *zone)
{
    int cpu;

    if (sizeof(struct per_cpu_zonestat) > 0)
        zone->per_cpu_zonestats = alloc_percpu(struct per_cpu_zonestat);

    zone->per_cpu_pageset = alloc_percpu(struct per_cpu_pages);
    for_each_possible_cpu(cpu) {
        struct per_cpu_pages *pcp;
        struct per_cpu_zonestat *pzstats;

        pcp = per_cpu_ptr(zone->per_cpu_pageset, cpu);
        pzstats = per_cpu_ptr(zone->per_cpu_zonestats, cpu);
        per_cpu_pages_init(pcp, pzstats);
    }

    zone_set_pageset_high_and_batch(zone, 0);
}

/*
 * Allocate per cpu pagesets and initialize them.
 * Before this call only boot pagesets were available.
 */
void __init setup_per_cpu_pageset(void)
{
    struct zone *zone;
    struct pglist_data *pgdat;

    for_each_populated_zone(zone)
        setup_zone_pageset(zone);

    for_each_online_pgdat(pgdat)
        pgdat->per_cpu_nodestats = alloc_percpu(struct per_cpu_nodestat);
}

/**
 * get_pfnblock_flags_mask - Return the requested group of flags for the pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 * @mask: mask of bits that the caller is interested in
 *
 * Return: pageblock_bits flags
 */
unsigned long
get_pfnblock_flags_mask(const struct page *page,
                        unsigned long pfn, unsigned long mask)
{
    return __get_pfnblock_flags_mask(page, pfn, mask);
}

static void check_free_page_bad(struct page *page)
{
    bad_page(page, page_bad_reason(page, PAGE_FLAGS_CHECK_AT_FREE));
}

static inline int check_free_page(struct page *page)
{
    if (likely(page_expected_state(page, PAGE_FLAGS_CHECK_AT_FREE)))
        return 0;

    /* Something has gone sideways, find it */
    check_free_page_bad(page);
    return 1;
}

/*
 * With DEBUG_VM disabled, order-0 pages being freed are checked only when
 * moving from pcp lists to free list in order to reduce overhead. With
 * debug_pagealloc enabled, they are checked also immediately when being freed
 * to the pcp lists.
 */
static bool free_pcp_prepare(struct page *page, unsigned int order)
{
    return free_pages_prepare(page, order, false, FPI_NONE);
}

static bool bulkfree_pcp_prepare(struct page *page)
{
    return check_free_page(page);
}

static bool
free_unref_page_prepare(struct page *page, unsigned long pfn,
                        unsigned int order)
{
    int migratetype;

    if (!free_pcp_prepare(page, order))
        return false;

    migratetype = get_pfnblock_migratetype(page, pfn);
    set_pcppage_migratetype(page, migratetype);
    return true;
}

static int nr_pcp_high(struct per_cpu_pages *pcp, struct zone *zone)
{
    int high = READ_ONCE(pcp->high);

    if (unlikely(!high))
        return 0;

    if (!test_bit(ZONE_RECLAIM_ACTIVE, &zone->flags))
        return high;

    /*
     * If reclaim is active, limit the number of pages that can be
     * stored on pcp lists
     */
    return min(READ_ONCE(pcp->batch) << 2, high);
}

static int nr_pcp_free(struct per_cpu_pages *pcp, int high, int batch)
{
    int min_nr_free, max_nr_free;

    /* Check for PCP disabled or boot pageset */
    if (unlikely(high < batch))
        return 1;

    /* Leave at least pcp->batch pages on the list */
    min_nr_free = batch;
    max_nr_free = high - batch;

    /*
     * Double the number of pages freed each time there is subsequent
     * freeing of pages without any allocation.
     */
    batch <<= pcp->free_factor;
    if (batch < max_nr_free)
        pcp->free_factor++;
    batch = clamp(batch, min_nr_free, max_nr_free);
    return batch;
}

static inline void prefetch_buddy(struct page *page)
{
    unsigned long pfn = page_to_pfn(page);
    unsigned long buddy_pfn = __find_buddy_pfn(pfn, 0);
    struct page *buddy = page + (buddy_pfn - pfn);

    prefetch(buddy);
}

/*
 * Frees a number of pages from the PCP lists
 * Assumes all pages on list are in same zone.
 * count is the number of pages to free.
 */
static void free_pcppages_bulk(struct zone *zone, int count,
                               struct per_cpu_pages *pcp)
{
    int pindex = 0;
    int batch_free = 0;
    int nr_freed = 0;
    unsigned int order;
    int prefetch_nr = READ_ONCE(pcp->batch);
    struct page *page, *tmp;
    LIST_HEAD(head);

    /*
     * Ensure proper count is passed which otherwise would stuck in the
     * below while (list_empty(list)) loop.
     */
    count = min(pcp->count, count);
    while (count > 0) {
        struct list_head *list;

        /*
         * Remove pages from lists in a round-robin fashion. A
         * batch_free count is maintained that is incremented when an
         * empty list is encountered.  This is so more pages are freed
         * off fuller lists instead of spinning excessively around empty
         * lists
         */
        do {
            batch_free++;
            if (++pindex == NR_PCP_LISTS)
                pindex = 0;
            list = &pcp->lists[pindex];
        } while (list_empty(list));

        /* This is the only non-empty list. Free them all. */
        if (batch_free == NR_PCP_LISTS)
            batch_free = count;

        order = pindex_to_order(pindex);
        BUILD_BUG_ON(MAX_ORDER >= (1<<NR_PCP_ORDER_WIDTH));
        do {
            page = list_last_entry(list, struct page, lru);
            /* must delete to avoid corrupting pcp list */
            list_del(&page->lru);
            nr_freed += 1 << order;
            count -= 1 << order;

            if (bulkfree_pcp_prepare(page))
                continue;

            /* Encode order with the migratetype */
            page->index <<= NR_PCP_ORDER_WIDTH;
            page->index |= order;

            list_add_tail(&page->lru, &head);

            /*
             * We are going to put the page back to the global
             * pool, prefetch its buddy to speed up later access
             * under zone->lock. It is believed the overhead of
             * an additional test and calculating buddy_pfn here
             * can be offset by reduced memory latency later. To
             * avoid excessive prefetching due to large count, only
             * prefetch buddy for the first pcp->batch nr of pages.
             */
            if (prefetch_nr) {
                prefetch_buddy(page);
                prefetch_nr--;
            }
        } while (count > 0 && --batch_free && !list_empty(list));
    }
    pcp->count -= nr_freed;

    /*
     * local_lock_irq held so equivalent to spin_lock_irqsave for
     * both PREEMPT_RT and non-PREEMPT_RT configurations.
     */
    spin_lock(&zone->lock);

    /*
     * Use safe version since after __free_one_page(),
     * page->lru.next will not point to original list.
     */
    list_for_each_entry_safe(page, tmp, &head, lru) {
        int mt = get_pcppage_migratetype(page);

        /* mt has been encoded with the order (see above) */
        order = mt & NR_PCP_ORDER_MASK;
        mt >>= NR_PCP_ORDER_WIDTH;

        __free_one_page(page, page_to_pfn(page), zone, order, mt, FPI_NONE);
    }

    spin_unlock(&zone->lock);
}

static void
free_unref_page_commit(struct page *page, unsigned long pfn,
                       int migratetype, unsigned int order)
{
    int high;
    int pindex;
    struct per_cpu_pages *pcp;
    struct zone *zone = page_zone(page);

    pcp = this_cpu_ptr(zone->per_cpu_pageset);
    pindex = order_to_pindex(migratetype, order);
    list_add(&page->lru, &pcp->lists[pindex]);
    pcp->count += 1 << order;
    high = nr_pcp_high(pcp, zone);
    if (pcp->count >= high) {
        int batch = READ_ONCE(pcp->batch);

        free_pcppages_bulk(zone, nr_pcp_free(pcp, high, batch), pcp);
    }
}

/*
 * Free a pcp page
 */
void free_unref_page(struct page *page, unsigned int order)
{
    int migratetype;
    unsigned long flags;
    unsigned long pfn = page_to_pfn(page);

    if (!free_unref_page_prepare(page, pfn, order))
        return;

    /*
     * We only track unmovable, reclaimable and movable on pcp lists.
     * Place ISOLATE pages on the isolated list because they are being
     * offlined but treat HIGHATOMIC as movable pages so we can get those
     * areas back if necessary. Otherwise, we may have to free
     * excessively into the page allocator
     */
    migratetype = get_pcppage_migratetype(page);
    if (unlikely(migratetype >= MIGRATE_PCPTYPES))
        migratetype = MIGRATE_MOVABLE;

    local_lock_irqsave(&pagesets.lock, flags);
    free_unref_page_commit(page, pfn, migratetype, order);
    local_unlock_irqrestore(&pagesets.lock, flags);
}

static inline void free_the_page(struct page *page, unsigned int order)
{
    if (pcp_allowed_order(order))       /* Via pcp? */
        free_unref_page(page, order);
    else
        __free_pages_ok(page, order, FPI_NONE);
}

/**
 * __free_pages - Free pages allocated with alloc_pages().
 * @page: The page pointer returned from alloc_pages().
 * @order: The order of the allocation.
 *
 * This function can free multi-page allocations that are not compound
 * pages.  It does not check that the @order passed in matches that of
 * the allocation, so it is easy to leak memory.  Freeing more memory
 * than was allocated will probably emit a warning.
 *
 * If the last reference to this page is speculative, it will be released
 * by put_page() which only frees the first page of a non-compound
 * allocation.  To prevent the remaining pages from being leaked, we free
 * the subsequent pages here.  If you want to use the page's reference
 * count to decide when to free the allocation, you should allocate a
 * compound page, and use put_page() instead of __free_pages().
 *
 * Context: May be called in interrupt context or while holding a normal
 * spinlock, but not in NMI context or while holding a raw spinlock.
 */
void __free_pages(struct page *page, unsigned int order)
{
    if (put_page_testzero(page))
        free_the_page(page, order);
    else if (!PageHead(page))
        while (order-- > 0)
            free_the_page(page + (1 << order), order);
}
EXPORT_SYMBOL(__free_pages);

void free_pages(unsigned long addr, unsigned int order)
{
    if (addr != 0) {
        VM_BUG_ON(!virt_addr_valid((void *)addr));
        __free_pages(virt_to_page((void *)addr), order);
    }
}
EXPORT_SYMBOL(free_pages);

/*
 * Common helper functions. Never use with __GFP_HIGHMEM because the returned
 * address cannot represent highmem pages. Use alloc_pages and then kmap if
 * you need to access high mem.
 */
unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
{
    struct page *page;

    page = alloc_pages(gfp_mask & ~__GFP_HIGHMEM, order);
    if (!page)
        return 0;
    return (unsigned long) page_address(page);
}
EXPORT_SYMBOL(__get_free_pages);

void __init mem_init_print_info(void)
{
    panic("%s: NO implementation!\n", __func__);
}
