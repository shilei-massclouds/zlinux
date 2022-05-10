/* SPDX-License-Identifier: GPL-2.0 */
#ifndef PAGE_FLAGS_LAYOUT_H
#define PAGE_FLAGS_LAYOUT_H

#include <linux/numa.h>
#include <generated/bounds.h>

/*
 * When a memory allocation must conform to specific limitations (such
 * as being suitable for DMA) the caller will pass in hints to the
 * allocator in the gfp_mask, in the zone modifier bits.  These bits
 * are used to select a priority ordered list of memory zones which
 * match the requested limits. See gfp_zone() in include/linux/gfp.h
 */
#if MAX_NR_ZONES < 2
#define ZONES_SHIFT 0
#elif MAX_NR_ZONES <= 2
#define ZONES_SHIFT 1
#elif MAX_NR_ZONES <= 4
#define ZONES_SHIFT 2
#elif MAX_NR_ZONES <= 8
#define ZONES_SHIFT 3
#else
#error ZONES_SHIFT "Too many zones configured"
#endif

#define ZONES_WIDTH     ZONES_SHIFT

#define SECTIONS_WIDTH      0

#define LAST_CPUPID_WIDTH   0

#if ZONES_WIDTH + SECTIONS_WIDTH + NODES_SHIFT <= BITS_PER_LONG - NR_PAGEFLAGS
#define NODES_WIDTH     NODES_SHIFT
#else
#define NODES_WIDTH     0
#endif

#define LAST_CPUPID_SHIFT 0

/*
 * Note that this #define MUST have a value so that it can be tested with
 * the IS_ENABLED() macro.
 */
#if NODES_SHIFT != 0 && NODES_WIDTH == 0
#define NODE_NOT_IN_PAGE_FLAGS  1
#endif

#endif /* _LINUX_PAGE_FLAGS_LAYOUT */
