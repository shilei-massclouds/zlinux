/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <linux/mmdebug.h>
#include <linux/mmzone.h>
#include <linux/stddef.h>
#include <linux/linkage.h>
#include <linux/topology.h>

/* Plain integer GFP bitmasks. Do not use this directly. */
#define ___GFP_DMA          0x01u
#define ___GFP_HIGHMEM      0x02u
#define ___GFP_DMA32        0x04u
#define ___GFP_MOVABLE      0x08u
#define ___GFP_RECLAIMABLE  0x10u
#define ___GFP_HIGH         0x20u
#define ___GFP_IO           0x40u
#define ___GFP_FS           0x80u
#define ___GFP_ZERO         0x100u
#define ___GFP_WRITE        0x1000u
#define ___GFP_NOWARN       0x2000u

#define ___GFP_DIRECT_RECLAIM   0x400u
#define ___GFP_KSWAPD_RECLAIM   0x800u

#define ___GFP_THISNODE     0x200000u

#define __GFP_IO    ((__force gfp_t)___GFP_IO)
#define __GFP_FS    ((__force gfp_t)___GFP_FS)
#define __GFP_KSWAPD_RECLAIM \
    ((__force gfp_t)___GFP_KSWAPD_RECLAIM) /* kswapd can wake */
#define __GFP_RECLAIM \
    ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))

/**
 * DOC: Page mobility and placement hints
 *
 * Page mobility and placement hints
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * These flags provide hints about how mobile the page is. Pages with similar
 * mobility are placed within the same pageblocks to minimise problems due
 * to external fragmentation.
 *
 * %__GFP_MOVABLE (also a zone modifier) indicates that the page can be
 * moved by page migration during memory compaction or can be reclaimed.
 *
 * %__GFP_RECLAIMABLE is used for slab allocations that specify
 * SLAB_RECLAIM_ACCOUNT and whose pages can be freed via shrinkers.
 *
 * %__GFP_WRITE indicates the caller intends to dirty the page. Where possible,
 * these pages will be spread between local zones to avoid all the dirty
 * pages being in one zone (fair zone allocation policy).
 *
 * %__GFP_HARDWALL enforces the cpuset memory allocation policy.
 *
 * %__GFP_THISNODE forces the allocation to be satisfied from the requested
 * node with no fallbacks or placement policy enforcements.
 *
 * %__GFP_ACCOUNT causes the allocation to be accounted to kmemcg.
 */
#define __GFP_RECLAIMABLE   ((__force gfp_t)___GFP_RECLAIMABLE)
#define __GFP_WRITE         ((__force gfp_t)___GFP_WRITE)
#define __GFP_THISNODE      ((__force gfp_t)___GFP_THISNODE)

/**
 * DOC: Action modifiers
 *
 * Action modifiers
 * ~~~~~~~~~~~~~~~~
 *
 * %__GFP_NOWARN suppresses allocation failure reports.
 *
 * %__GFP_COMP address compound page metadata.
 *
 * %__GFP_ZERO returns a zeroed page on success.
 *
 * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
 * __GFP_ZERO is set.
 *
 * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
 * on deallocation. Typically used for userspace pages. Currently only has an
 * effect in HW tags mode.
 */
#define __GFP_NOWARN    ((__force gfp_t)___GFP_NOWARN)
#define __GFP_ZERO      ((__force gfp_t)___GFP_ZERO)

/*
 * Physical address zone modifiers (see linux/mmzone.h - low four bits)
 *
 * Do not put any conditional on these. If necessary modify the definitions
 * without the underscores and use them consistently. The definitions here may
 * be used in bit comparisons.
 */
#define __GFP_DMA       ((__force gfp_t)___GFP_DMA)
#define __GFP_HIGHMEM   ((__force gfp_t)___GFP_HIGHMEM)
#define __GFP_DMA32     ((__force gfp_t)___GFP_DMA32)
#define __GFP_MOVABLE   ((__force gfp_t)___GFP_MOVABLE)

#define GFP_ZONEMASK    (__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)


/* Room for N __GFP_FOO bits */
#define __GFP_BITS_SHIFT    (25)
#define __GFP_BITS_MASK     ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))

#define GFP_KERNEL  (__GFP_RECLAIM | __GFP_IO | __GFP_FS)

struct page *
__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
              nodemask_t *nodemask);

/*
 * Allocate pages, preferring the node given as nid. The node must be valid and
 * online. For more general interface, see alloc_pages_node().
 */
static inline struct page *
__alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
    VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
    VM_WARN_ON((gfp_mask & __GFP_THISNODE) && !node_online(nid));

    return __alloc_pages(gfp_mask, order, nid, NULL);
}

/*
 * Allocate pages, preferring the node given as nid. When nid == NUMA_NO_NODE,
 * prefer the current CPU's closest node. Otherwise node must be valid and
 * online.
 */
static inline struct page *
alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
    if (nid == NUMA_NO_NODE)
        nid = numa_mem_id();

    return __alloc_pages_node(nid, gfp_mask, order);
}

static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
{
    return alloc_pages_node(numa_node_id(), gfp_mask, order);
}

#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

#define OPT_ZONE_DMA        ZONE_NORMAL
#define OPT_ZONE_HIGHMEM    ZONE_NORMAL
#define OPT_ZONE_DMA32      ZONE_DMA32

#define GFP_ZONES_SHIFT ZONES_SHIFT

#define GFP_ZONE_TABLE ( \
    (ZONE_NORMAL << 0 * GFP_ZONES_SHIFT) | \
    (OPT_ZONE_DMA << ___GFP_DMA * GFP_ZONES_SHIFT) | \
    (OPT_ZONE_HIGHMEM << ___GFP_HIGHMEM * GFP_ZONES_SHIFT) | \
    (OPT_ZONE_DMA32 << ___GFP_DMA32 * GFP_ZONES_SHIFT) | \
    (ZONE_NORMAL << ___GFP_MOVABLE * GFP_ZONES_SHIFT) | \
    (OPT_ZONE_DMA << (___GFP_MOVABLE | ___GFP_DMA) * GFP_ZONES_SHIFT) | \
    (ZONE_MOVABLE << (___GFP_MOVABLE | ___GFP_HIGHMEM) * GFP_ZONES_SHIFT) | \
    (OPT_ZONE_DMA32 << (___GFP_MOVABLE | ___GFP_DMA32) * GFP_ZONES_SHIFT) \
)

/*
 * GFP_ZONE_BAD is a bitmap for all combinations of __GFP_DMA, __GFP_DMA32
 * __GFP_HIGHMEM and __GFP_MOVABLE that are not permitted. One flag per
 * entry starting with bit 0. Bit is set if the combination is not
 * allowed.
 */
#define GFP_ZONE_BAD ( \
    1 << (___GFP_DMA | ___GFP_HIGHMEM) | \
    1 << (___GFP_DMA | ___GFP_DMA32) | \
    1 << (___GFP_DMA32 | ___GFP_HIGHMEM) | \
    1 << (___GFP_DMA | ___GFP_DMA32 | ___GFP_HIGHMEM) | \
    1 << (___GFP_MOVABLE | ___GFP_HIGHMEM | ___GFP_DMA) | \
    1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_DMA) | \
    1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_HIGHMEM) | \
    1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_DMA | ___GFP_HIGHMEM) \
)

static inline enum zone_type gfp_zone(gfp_t flags)
{
    enum zone_type z;
    int bit = (__force int) (flags & GFP_ZONEMASK);

    z = (GFP_ZONE_TABLE >> (bit * GFP_ZONES_SHIFT)) &
        ((1 << GFP_ZONES_SHIFT) - 1);
    VM_BUG_ON((GFP_ZONE_BAD >> bit) & 1);
    return z;
}

static inline int gfp_zonelist(gfp_t flags)
{
    return ZONELIST_FALLBACK;
}

/*
 * We get the zone list from the current node and the gfp_mask.
 * This zone list contains a maximum of MAX_NUMNODES*MAX_NR_ZONES zones.
 * There are two zonelists per node, one for all zones with memory and
 * one containing just zones from the node the zonelist belongs to.
 *
 * For the case of non-NUMA systems the NODE_DATA() gets optimized to
 * &contig_page_data at compile-time.
 */
static inline struct zonelist *node_zonelist(int nid, gfp_t flags)
{
    return NODE_DATA(nid)->node_zonelists + gfp_zonelist(flags);
}

/* Convert GFP flags to their corresponding migrate type */
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)
#define GFP_MOVABLE_SHIFT 3

static inline int gfp_migratetype(const gfp_t gfp_flags)
{
    VM_WARN_ON((gfp_flags & GFP_MOVABLE_MASK) == GFP_MOVABLE_MASK);
    BUILD_BUG_ON((1UL << GFP_MOVABLE_SHIFT) != ___GFP_MOVABLE);
    BUILD_BUG_ON((___GFP_MOVABLE >> GFP_MOVABLE_SHIFT) != MIGRATE_MOVABLE);

    if (unlikely(page_group_by_mobility_disabled))
        return MIGRATE_UNMOVABLE;

    /* Group based on mobility */
    return (gfp_flags & GFP_MOVABLE_MASK) >> GFP_MOVABLE_SHIFT;
}
#undef GFP_MOVABLE_MASK
#undef GFP_MOVABLE_SHIFT

#endif /* __LINUX_GFP_H */
