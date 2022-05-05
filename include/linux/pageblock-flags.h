/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Macros for manipulating and testing flags related to a
 * pageblock_nr_pages number of pages.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Original author, Mel Gorman
 * Major cleanups and reduction of bit operations, Andy Whitcroft
 */
#ifndef PAGEBLOCK_FLAGS_H
#define PAGEBLOCK_FLAGS_H

#include <linux/types.h>

#define PB_migratetype_bits 3
/* Bit indices that affect a whole block of pages */
enum pageblock_bits {
    PB_migrate,
    /* 3 bits required for migrate types */
    PB_migrate_end = PB_migrate + PB_migratetype_bits - 1,
    PB_migrate_skip,    /* If set the block is skipped by compaction */

    /*
     * Assume the bits will always align on a word. If this assumption
     * changes then get/set pageblock needs updating.
     */
    NR_PAGEBLOCK_BITS
};

/* If huge pages are not used, group by MAX_ORDER_NR_PAGES */
#define pageblock_order     (MAX_ORDER-1)

#define pageblock_nr_pages  (1UL << pageblock_order)

#endif  /* PAGEBLOCK_FLAGS_H */
