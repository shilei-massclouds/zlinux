/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/numa.h>
#include <linux/page-flags.h>
#include <linux/pageblock-flags.h>
#include <linux/atomic.h>

/* Free memory management - zoned buddy allocator.  */
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))

struct per_cpu_nodestat {
    s8 stat_threshold;
    //s8 vm_node_stat_diff[NR_VM_NODE_STAT_ITEMS];
};

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

#ifndef __GENERATING_BOUNDS_H

/*
 * The array of struct pages for flatmem.
 * It must be declared for SPARSEMEM as well because there are configurations
 * that rely on that.
 */
extern struct page *mem_map;

/* Maximum number of zones on a zonelist */
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)

enum migratetype {
    MIGRATE_UNMOVABLE,
    MIGRATE_MOVABLE,
    MIGRATE_RECLAIMABLE,
    MIGRATE_PCPTYPES,   /* the number of types on the pcp lists */
    MIGRATE_HIGHATOMIC = MIGRATE_PCPTYPES,
    MIGRATE_TYPES
};

struct free_area {
    struct list_head    free_list[MIGRATE_TYPES];
    unsigned long       nr_free;
};

struct zone {

    struct pglist_data  *zone_pgdat;

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

    /* free areas of different sizes */
    struct free_area    free_area[MAX_ORDER];

    /* Primarily protects free_area */
    spinlock_t          lock;

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

    enum zone_type kswapd_highest_zoneidx;

    /* Per-node vmstats */
    struct per_cpu_nodestat __percpu *per_cpu_nodestats;
} pg_data_t;

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

#endif /* !__GENERATING_BOUNDS_H */
#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_MMZONE_H */
