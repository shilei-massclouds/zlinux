/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/seqlock.h>
#include <linux/nodemask.h>
#include <linux/pageblock-flags.h>
#include <linux/page-flags-layout.h>
#include <linux/atomic.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/local_lock.h>
#include <asm/page.h>

/*
 * PAGE_ALLOC_COSTLY_ORDER is the order at which allocations are deemed
 * costly to service.  That is between allocation orders which should
 * coalesce naturally under reasonable reclaim pressure and those which
 * will not.
 */
#define PAGE_ALLOC_COSTLY_ORDER 3

#define NR_PCP_THP 0
#define NR_PCP_LISTS \
    (MIGRATE_PCPTYPES * (PAGE_ALLOC_COSTLY_ORDER + 1 + NR_PCP_THP))

/*
 * Shift to encode migratetype and order in the same integer, with order
 * in the least significant bits.
 */
#define NR_PCP_ORDER_WIDTH 8
#define NR_PCP_ORDER_MASK ((1<<NR_PCP_ORDER_WIDTH) - 1)

/* Free memory management - zoned buddy allocator.  */
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))

#define min_wmark_pages(z)  (z->_watermark[WMARK_MIN] + z->watermark_boost)
#define low_wmark_pages(z)  (z->_watermark[WMARK_LOW] + z->watermark_boost)
#define high_wmark_pages(z) (z->_watermark[WMARK_HIGH] + z->watermark_boost)
#define wmark_pages(z, i)   (z->_watermark[i] + z->watermark_boost)

/*
 * The "priority" of VM scanning is how much of the queues we will scan in one
 * go. A value of 12 for DEF_PRIORITY implies that we will scan 1/4096th of the
 * queues ("queue_length >> 12") during an aging round.
 */
#define DEF_PRIORITY 12

enum migratetype {
    MIGRATE_UNMOVABLE,
    MIGRATE_MOVABLE,
    MIGRATE_RECLAIMABLE,
    MIGRATE_PCPTYPES,   /* the number of types on the pcp lists */
    MIGRATE_HIGHATOMIC = MIGRATE_PCPTYPES,
    MIGRATE_TYPES
};

#define is_migrate_cma(migratetype) false
#define is_migrate_cma_page(_page)  false

enum pgdat_flags {
    PGDAT_DIRTY,    /* reclaim scanning has recently found
                     * many dirty file pages at the tail
                     * of the LRU.
                     */
    PGDAT_WRITEBACK,        /* reclaim scanning has recently found
                             * many pages under writeback
                             */
    PGDAT_RECLAIM_LOCKED,   /* prevents concurrent reclaim */
};

enum zone_flags {
    ZONE_BOOSTED_WATERMARK, /* zone recently boosted watermarks.
                             * Cleared when kswapd is woken. */
    ZONE_RECLAIM_ACTIVE,    /* kswapd may be scanning the zone. */
};

enum zone_stat_item {
    /* First 128 byte cacheline (assuming 64 bit words) */
    NR_FREE_PAGES,
    NR_ZONE_LRU_BASE, /* Used only for compaction and reclaim retry */
    NR_ZONE_INACTIVE_ANON = NR_ZONE_LRU_BASE,
    NR_ZONE_ACTIVE_ANON,
    NR_ZONE_INACTIVE_FILE,
    NR_ZONE_ACTIVE_FILE,
    NR_ZONE_UNEVICTABLE,
    NR_ZONE_WRITE_PENDING,  /* Count of dirty, writeback and unstable pages */
    NR_MLOCK,       /* mlock()ed pages found and moved off LRU */
    /* Second 128 byte cacheline */
    NR_BOUNCE,
    NR_FREE_CMA_PAGES,
    NR_VM_ZONE_STAT_ITEMS
};

enum node_stat_item {
    NR_LRU_BASE,
    NR_INACTIVE_ANON = NR_LRU_BASE, /* must match order of LRU_[IN]ACTIVE */
    NR_ACTIVE_ANON,     /*  "     "     "   "       "         */
    NR_INACTIVE_FILE,   /*  "     "     "   "       "         */
    NR_ACTIVE_FILE,     /*  "     "     "   "       "         */
    NR_SLAB_RECLAIMABLE_B,
    NR_SLAB_UNRECLAIMABLE_B,
    NR_ISOLATED_ANON,   /* Temporary isolated pages from anon lru */
    NR_ISOLATED_FILE,   /* Temporary isolated pages from file lru */
    WORKINGSET_NODES,
    WORKINGSET_REFAULT_BASE,
    WORKINGSET_REFAULT_ANON = WORKINGSET_REFAULT_BASE,
    WORKINGSET_REFAULT_FILE,
    WORKINGSET_ACTIVATE_BASE,
    WORKINGSET_ACTIVATE_ANON = WORKINGSET_ACTIVATE_BASE,
    WORKINGSET_ACTIVATE_FILE,
    WORKINGSET_RESTORE_BASE,
    WORKINGSET_RESTORE_ANON = WORKINGSET_RESTORE_BASE,
    WORKINGSET_RESTORE_FILE,
    WORKINGSET_NODERECLAIM,
    NR_ANON_MAPPED,     /* Mapped anonymous pages */
    NR_FILE_MAPPED,     /* pagecache pages mapped into pagetables.
                           only modified from process context */
    NR_FILE_PAGES,
    NR_FILE_DIRTY,
    NR_WRITEBACK,
    NR_SHMEM,           /* shmem pages (included tmpfs/GEM pages) */
    NR_SHMEM_PMDMAPPED,
    NR_FILE_PMDMAPPED,
    NR_ANON_THPS,
    NR_THROTTLED_WRITTEN,   /* NR_WRITTEN while reclaim throttled */
    NR_KERNEL_STACK_KB, /* measured in KiB */
    NR_PAGETABLE,       /* used for pagetables */
    NR_VM_NODE_STAT_ITEMS
};

/* Fields and list protected by pagesets local_lock in page_alloc.c */
struct per_cpu_pages {
    int count;          /* number of pages in the list */
    int high;           /* high watermark, emptying needed */
    int batch;          /* chunk size for buddy add/remove */
    short free_factor;  /* batch scaling factor during free */

    /* Lists of pages, one per migrate type stored on the pcp-lists */
    struct list_head lists[NR_PCP_LISTS];
};

struct per_cpu_zonestat {
    s8 vm_stat_diff[NR_VM_ZONE_STAT_ITEMS];
    s8 stat_threshold;
};

struct per_cpu_nodestat {
    s8 stat_threshold;
    s8 vm_node_stat_diff[NR_VM_NODE_STAT_ITEMS];
};

enum zone_watermarks {
    WMARK_MIN,
    WMARK_LOW,
    WMARK_HIGH,
    WMARK_PROMO,
    NR_WMARK
};

/*
 * Add a wild amount of padding here to ensure data fall into separate
 * cachelines.  There are very few zone structures in the machine, so space
 * consumption is not a concern here.
 */
struct zone_padding {
    char x[0];
} ____cacheline_internodealigned_in_smp;
#define ZONE_PADDING(name)  struct zone_padding name;

#endif /* !__GENERATING_BOUNDS_H */

enum zone_type {
    /*
     * ZONE_DMA and ZONE_DMA32 are used when there are peripherals not able
     * to DMA to all of the addressable memory (ZONE_NORMAL).
     * On architectures where this area covers the whole 32 bit address
     * space ZONE_DMA32 is used. ZONE_DMA is left for the ones with smaller
     * DMA addressing constraints. This distinction is important as a 32bit
     * DMA mask is assumed when ZONE_DMA32 is defined. Some 64-bit
     * platforms may need both zones as they support peripherals with
     * different DMA addressing limitations.
     *
     * Some examples:
     *
     *  - i386 and x86_64 have a fixed 16M ZONE_DMA and ZONE_DMA32 for the
     *    rest of the lower 4G.
     *
     *  - arm only uses ZONE_DMA, the size, up to 4G, may vary depending on
     *    the specific device.
     *
     *  - arm64 has a fixed 1G ZONE_DMA and ZONE_DMA32 for the rest of the
     *    lower 4G.
     *
     *  - powerpc only uses ZONE_DMA, the size, up to 2G, may vary
     *    depending on the specific device.
     *
     *  - s390 uses ZONE_DMA fixed to the lower 2G.
     *
     *  - ia64 and riscv only use ZONE_DMA32.
     *
     *  - parisc uses neither.
     */
#ifdef CONFIG_ZONE_DMA32
    ZONE_DMA32,
#endif
    /*
     * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
     * performed on pages in ZONE_NORMAL if the DMA devices support
     * transfers to all addressable memory.
     */
    ZONE_NORMAL,
    ZONE_MOVABLE,

    __MAX_NR_ZONES
};

/*
 * We do arithmetic on the LRU lists in various places in the code,
 * so it is important to keep the active lists LRU_ACTIVE higher in
 * the array than the corresponding inactive lists, and to keep
 * the *_FILE lists LRU_FILE higher than the corresponding _ANON lists.
 *
 * This has to be kept in sync with the statistics in zone_stat_item
 * above and the descriptions in vmstat_text in mm/vmstat.c
 */
#define LRU_BASE    0
#define LRU_ACTIVE  1
#define LRU_FILE    2

enum lru_list {
    LRU_INACTIVE_ANON   = LRU_BASE,
    LRU_ACTIVE_ANON     = LRU_BASE + LRU_ACTIVE,
    LRU_INACTIVE_FILE   = LRU_BASE + LRU_FILE,
    LRU_ACTIVE_FILE     = LRU_BASE + LRU_FILE + LRU_ACTIVE,
    LRU_UNEVICTABLE,
    NR_LRU_LISTS
};

#ifndef __GENERATING_BOUNDS_H

#define ANON_AND_FILE 2

enum lruvec_flags {
    LRUVEC_CONGESTED,       /* lruvec has many dirty pages
                             * backed by a congested BDI
                             * */
};

struct lruvec {
    struct list_head        lists[NR_LRU_LISTS];
    /* per lruvec lru_lock for memcg */
    spinlock_t              lru_lock;
    /*
     * These track the cost of reclaiming one LRU - file or anon -
     * over the other. As the observed cost of reclaiming one LRU
     * increases, the reclaim scan balance tips toward the other.
     */
    unsigned long           anon_cost;
    unsigned long           file_cost;
    /* Non-resident age, driven by LRU movement */
    atomic_long_t           nonresident_age;
    /* Refaults at the time of last reclaim cycle */
    unsigned long           refaults[ANON_AND_FILE];
    /* Various lruvec state flags (enum lruvec_flags) */
    unsigned long           flags;
};

/*
 * The array of struct pages for flatmem.
 * It must be declared for SPARSEMEM as well because there are configurations
 * that rely on that.
 */
extern struct page *mem_map;

/* Maximum number of zones on a zonelist */
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)

struct free_area {
    struct list_head    free_list[MIGRATE_TYPES];
    unsigned long       nr_free;
};

struct zone {

    /* zone watermarks, access with *_wmark_pages(zone) macros */
    unsigned long _watermark[NR_WMARK];
    unsigned long watermark_boost;

    unsigned long nr_reserved_highatomic;

    /*
     * We don't know if the memory that we're going to allocate will be
     * freeable or/and it will be released eventually, so to avoid totally
     * wasting several GB of ram we must reserve some of the lower zone
     * memory (otherwise we risk to run OOM on the lower zones despite
     * there being tons of freeable ram on the higher zones).  This array is
     * recalculated at runtime if the sysctl_lowmem_reserve_ratio sysctl
     * changes.
     */
    long lowmem_reserve[MAX_NR_ZONES];

    struct pglist_data  *zone_pgdat;

    struct per_cpu_zonestat __percpu *per_cpu_zonestats;

    /*
     * When free pages are below this point, additional steps are taken
     * when reading the number of free pages to avoid per-cpu counter
     * drift allowing watermarks to be breached
     */
    unsigned long percpu_drift_mark;

    /*
     * the high and batch values are copied to individual pagesets for
     * faster access
     */
    int pageset_high;
    int pageset_batch;

    struct per_cpu_pages __percpu *per_cpu_pageset;

    /* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
    unsigned long       zone_start_pfn;

    /*
     * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
     * In SPARSEMEM, this map is stored in struct mem_section
     */
    unsigned long       *pageblock_flags;

    atomic_long_t       managed_pages;
    unsigned long       spanned_pages;
    unsigned long       present_pages;

    const char          *name;

    int                 initialized;

    /* Write-intensive fields used from the page allocator */
    ZONE_PADDING(_pad1_)

    /* free areas of different sizes */
    struct free_area    free_area[MAX_ORDER];

    /* zone flags, see below */
    unsigned long       flags;

    /* Primarily protects free_area */
    spinlock_t          lock;

    /* Write-intensive fields used by compaction and vmstats. */
    ZONE_PADDING(_pad2_)

    /* Set to true when the PG_migrate_skip bits should be cleared */
    bool compact_blockskip_flush;

    bool contiguous;

    ZONE_PADDING(_pad3_)
    /* Zone statistics */
    atomic_long_t       vm_stat[NR_VM_ZONE_STAT_ITEMS];

} ____cacheline_internodealigned_in_smp;

enum {
    ZONELIST_FALLBACK,  /* zonelist with fallback */
    MAX_ZONELISTS
};

/*
 * This struct contains information about a zone in a zonelist. It is stored
 * here to avoid dereferences into large structures and lookups of tables
 */
struct zoneref {
    struct zone *zone;  /* Pointer to actual zone */
    int zone_idx;       /* zone_idx(zoneref->zone) */
};

/*
 * One allocation request operates on a zonelist. A zonelist
 * is a list of zones, the first one is the 'goal' of the
 * allocation, the other zones are fallback zones, in decreasing
 * priority.
 *
 * To speed the reading of the zonelist, the zonerefs contain the zone index
 * of the entry being read. Helper functions to access information given
 * a struct zoneref are
 *
 * zonelist_zone()  - Return the struct zone * for an entry in _zonerefs
 * zonelist_zone_idx()  - Return the index of the zone for an entry
 * zonelist_node_idx()  - Return the index of the node for an entry
 */
struct zonelist {
    struct zoneref _zonerefs[MAX_ZONES_PER_ZONELIST + 1];
};

enum vmscan_throttle_state {
    VMSCAN_THROTTLE_WRITEBACK,
    VMSCAN_THROTTLE_ISOLATED,
    VMSCAN_THROTTLE_NOPROGRESS,
    VMSCAN_THROTTLE_CONGESTED,
    NR_VMSCAN_THROTTLE,
};

/*
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it's memory layout. On UMA machines there is a single pglist_data which
 * describes the whole memory.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */
typedef struct pglist_data {
    /*
     * node_zones contains just the zones for THIS node. Not all of the
     * zones may be populated, but it is the full list. It is referenced by
     * this node's node_zonelists as well as other node's node_zonelists.
     */
    struct zone node_zones[MAX_NR_ZONES];

    /*
     * node_zonelists contains references to all zones in all nodes.
     * Generally the first zones will be references to this node's
     * node_zones.
     */
    struct zonelist node_zonelists[MAX_ZONELISTS];

    int nr_zones; /* number of populated zones in this node */

    struct page *node_mem_map;

    unsigned long node_start_pfn;
    unsigned long node_present_pages; /* total number of physical pages */
    unsigned long node_spanned_pages; /* total size of physical page range, including holes */

    int node_id;
    wait_queue_head_t kswapd_wait;
    wait_queue_head_t pfmemalloc_wait;

    /* workqueues for throttling reclaim for different reasons. */
    wait_queue_head_t reclaim_wait[NR_VMSCAN_THROTTLE];

    int kswapd_order;
    enum zone_type kswapd_highest_zoneidx;

    int kswapd_failures;        /* Number of 'reclaimed == 0' runs */

#if 0
    int kcompactd_max_order;
    enum zone_type kcompactd_highest_zoneidx;
    wait_queue_head_t kcompactd_wait;
    struct task_struct *kcompactd;
    bool proactive_compact_trigger;
#endif

    /* nr of writeback-throttled tasks */
    atomic_t nr_writeback_throttled;

    /* nr pages written while throttled
     * when throttling started. */
    unsigned long nr_reclaim_start;

    /* Protected by mem_hotplug_begin/end() */
    struct task_struct *kswapd;

    /*
     * This is a per-node reserve of pages that are not available
     * to userspace allocations.
     */
    unsigned long totalreserve_pages;

    /* Write-intensive fields used by page reclaim */
    ZONE_PADDING(_pad1_)

    /* Fields commonly accessed by the page reclaim scanner */

    /*
     * NOTE: THIS IS UNUSED IF MEMCG IS ENABLED.
     *
     * Use mem_cgroup_lruvec() to look up lruvecs.
     */
    struct lruvec       __lruvec;

    unsigned long       flags;

    ZONE_PADDING(_pad2_)

    /* Per-node vmstats */
    struct per_cpu_nodestat __percpu *per_cpu_nodestats;
    atomic_long_t vm_stat[NR_VM_NODE_STAT_ITEMS];
} pg_data_t;

#define node_present_pages(nid) (NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid) (NODE_DATA(nid)->node_spanned_pages)

extern struct pglist_data contig_page_data;
static inline struct pglist_data *NODE_DATA(int nid)
{
    return &contig_page_data;
}

static inline unsigned long pgdat_end_pfn(pg_data_t *pgdat)
{
    return pgdat->node_start_pfn + pgdat->node_spanned_pages;
}

static inline void zone_set_nid(struct zone *zone, int nid) {}

/* Returns true if a zone has memory */
static inline bool populated_zone(struct zone *zone)
{
    return zone->present_pages;
}

static inline int zone_to_nid(struct zone *zone)
{
    return 0;
}

extern void
init_currently_empty_zone(struct zone *zone,
                          unsigned long start_pfn, unsigned long size);

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
#define zone_idx(zone)  ((zone) - (zone)->zone_pgdat->node_zones)

#define for_each_migratetype_order(order, type) \
    for (order = 0; order < MAX_ORDER; order++) \
        for (type = 0; type < MIGRATE_TYPES; type++)

/*
 * Memory initialization context, use to differentiate memory added by
 * the platform statically or via memory hotplug interface.
 */
enum meminit_context {
    MEMINIT_EARLY,
    MEMINIT_HOTPLUG,
};

#define MIGRATETYPE_MASK ((1UL << PB_migratetype_bits) - 1)

static inline unsigned long zone_end_pfn(const struct zone *zone)
{
    return zone->zone_start_pfn + zone->spanned_pages;
}

static inline bool zone_spans_pfn(const struct zone *zone, unsigned long pfn)
{
    return zone->zone_start_pfn <= pfn && pfn < zone_end_pfn(zone);
}

extern int page_group_by_mobility_disabled;

static inline int zonelist_zone_idx(struct zoneref *zoneref)
{
    return zoneref->zone_idx;
}

struct zoneref *
__next_zones_zonelist(struct zoneref *z,
                      enum zone_type highest_zoneidx,
                      nodemask_t *nodes);

/**
 * next_zones_zonelist - Returns the next zone at or below highest_zoneidx within the allowed nodemask using a cursor within a zonelist as a starting point
 * @z: The cursor used as a starting point for the search
 * @highest_zoneidx: The zone index of the highest zone to return
 * @nodes: An optional nodemask to filter the zonelist with
 *
 * This function returns the next zone at or below a given zone index that is
 * within the allowed nodemask using a cursor as the starting point for the
 * search. The zoneref returned is a cursor that represents the current zone
 * being examined. It should be advanced by one before calling
 * next_zones_zonelist again.
 *
 * Return: the next zone at or below highest_zoneidx within the allowed
 * nodemask using a cursor within a zonelist as a starting point
 */
static __always_inline struct zoneref *
next_zones_zonelist(struct zoneref *z,
                    enum zone_type highest_zoneidx,
                    nodemask_t *nodes)
{
    if (likely(!nodes && zonelist_zone_idx(z) <= highest_zoneidx))
        return z;
    return __next_zones_zonelist(z, highest_zoneidx, nodes);
}

/**
 * first_zones_zonelist - Returns the first zone at or below highest_zoneidx within the allowed nodemask in a zonelist
 * @zonelist: The zonelist to search for a suitable zone
 * @highest_zoneidx: The zone index of the highest zone to return
 * @nodes: An optional nodemask to filter the zonelist with
 *
 * This function returns the first zone at or below a given zone index that is
 * within the allowed nodemask. The zoneref returned is a cursor that can be
 * used to iterate the zonelist with next_zones_zonelist by advancing it by
 * one before calling.
 *
 * When no eligible zone is found, zoneref->zone is NULL (zoneref itself is
 * never NULL). This may happen either genuinely, or due to concurrent nodemask
 * update due to cpuset modification.
 *
 * Return: Zoneref pointer for the first suitable zone found
 */
static inline struct zoneref *
first_zones_zonelist(struct zonelist *zonelist,
                     enum zone_type highest_zoneidx,
                     nodemask_t *nodes)
{
    return next_zones_zonelist(zonelist->_zonerefs, highest_zoneidx, nodes);
}

void build_all_zonelists(pg_data_t *pgdat);

static inline unsigned long zone_managed_pages(struct zone *zone)
{
    return (unsigned long)atomic_long_read(&zone->managed_pages);
}

/*
 * Returns true if a zone has pages managed by the buddy allocator.
 * All the reclaim decisions have to use this function rather than
 * populated_zone(). If the whole zone is reserved then we can easily
 * end up with populated_zone() && !managed_zone().
 */
static inline bool managed_zone(struct zone *zone)
{
    return zone_managed_pages(zone);
}

static inline struct zone *zonelist_zone(struct zoneref *zoneref)
{
    return zoneref->zone;
}

#define for_next_zone_zonelist_nodemask(zone, z, highidx, nodemask) \
    for (zone = z->zone;    \
         zone;              \
         z = next_zones_zonelist(++z, highidx, nodemask), \
         zone = zonelist_zone(z))

static inline struct page *
get_page_from_free_area(struct free_area *area, int migratetype)
{
    return list_first_entry_or_null(&area->free_list[migratetype],
                                    struct page, lru);
}

static inline bool
free_area_empty(struct free_area *area, int migratetype)
{
    return list_empty(&area->free_list[migratetype]);
}

extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);

/**
 * for_each_online_pgdat - helper macro to iterate over all online nodes
 * @pgdat: pointer to a pg_data_t variable
 */
#define for_each_online_pgdat(pgdat)            \
    for (pgdat = first_online_pgdat();      \
         pgdat;                 \
         pgdat = next_online_pgdat(pgdat))

static inline bool zone_is_initialized(struct zone *zone)
{
    return zone->initialized;
}

/* LRU Isolation modes. */
typedef unsigned __bitwise isolate_mode_t;

extern struct zone *next_zone(struct zone *zone);

#define for_each_populated_zone(zone)               \
    for (zone = (first_online_pgdat())->node_zones; \
         zone;                  \
         zone = next_zone(zone))            \
        if (!populated_zone(zone))      \
            ; /* do nothing */      \
        else

#define get_pageblock_migratetype(page) \
    get_pfnblock_flags_mask(page, page_to_pfn(page), MIGRATETYPE_MASK)

/**
 * for_each_zone_zonelist_nodemask - helper macro to iterate over valid zones in a zonelist at or below a given zone index and within a nodemask
 * @zone: The current zone in the iterator
 * @z: The current pointer within zonelist->_zonerefs being iterated
 * @zlist: The zonelist being iterated
 * @highidx: The zone index of the highest zone to return
 * @nodemask: Nodemask allowed by the allocator
 *
 * This iterator iterates though all zones at or below a given zone index and
 * within a given nodemask
 */
#define for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
    for (z = first_zones_zonelist(zlist, highidx, nodemask),    \
         zone = zonelist_zone(z);                               \
         zone;                                                  \
         z = next_zones_zonelist(++z, highidx, nodemask),       \
         zone = zonelist_zone(z))

/**
 * for_each_zone_zonelist - helper macro to iterate over valid zones in a zonelist at or below a given zone index
 * @zone: The current zone in the iterator
 * @z: The current pointer within zonelist->zones being iterated
 * @zlist: The zonelist being iterated
 * @highidx: The zone index of the highest zone to return
 *
 * This iterator iterates though all zones at or below a given zone index.
 */
#define for_each_zone_zonelist(zone, z, zlist, highidx) \
    for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, NULL)

static inline struct pglist_data *lruvec_pgdat(struct lruvec *lruvec)
{
    return container_of(lruvec, struct pglist_data, __lruvec);
}

extern void lruvec_init(struct lruvec *lruvec);

#define for_each_lru(lru) for (lru = 0; lru < NR_LRU_LISTS; lru++)

/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone: pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in.
 */
#define for_each_zone(zone)                 \
    for (zone = (first_online_pgdat())->node_zones; \
         zone;                  \
         zone = next_zone(zone))

/**
 * is_highmem - helper function to quickly check if a struct zone is a
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone: pointer to struct zone variable
 * Return: 1 for a highmem zone, 0 otherwise
 */
static inline int is_highmem(struct zone *zone)
{
    return 0;
}

#define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++)

static inline bool is_file_lru(enum lru_list lru)
{
    return (lru == LRU_INACTIVE_FILE || lru == LRU_ACTIVE_FILE);
}

static inline bool is_active_lru(enum lru_list lru)
{
    return (lru == LRU_ACTIVE_ANON || lru == LRU_ACTIVE_FILE);
}

bool zone_watermark_ok_safe(struct zone *z, unsigned int order,
                            unsigned long mark, int highest_zoneidx);

#endif /* !__GENERATING_BOUNDS_H */
#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_MMZONE_H */
