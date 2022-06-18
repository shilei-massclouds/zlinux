/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/linux/idr.h
 *
 * 2002-10-18  written by Jim Houston jim.houston@ccur.com
 *  Copyright (C) 2002 by Concurrent Computer Corporation
 *
 * Small id to pointer translation service avoiding fixed sized
 * tables.
 */

#ifndef __IDR_H__
#define __IDR_H__

#include <linux/radix-tree.h>
#include <linux/gfp.h>
#include <linux/percpu.h>

/*
 * The IDR API does not expose the tagging functionality of the radix tree
 * to users.  Use tag 0 to track whether a node has free space below it.
 */
#define IDR_FREE    0

/* Set the IDR flag and the IDR_FREE tag */
#define IDR_RT_MARKER \
    (ROOT_IS_IDR | (__force gfp_t)(1 << (ROOT_TAG_SHIFT + IDR_FREE)))

#define IDR_INIT_BASE(name, base) {                 \
    .idr_rt   = RADIX_TREE_INIT(name, IDR_RT_MARKER), \
    .idr_base = (base),                             \
    .idr_next = 0,                                  \
}

/**
 * IDR_INIT() - Initialise an IDR.
 * @name: Name of IDR.
 *
 * A freshly-initialised IDR contains no IDs.
 */
#define IDR_INIT(name)  IDR_INIT_BASE(name, 0)

void idr_preload(gfp_t gfp_mask);

struct idr {
    struct radix_tree_root  idr_rt;
    unsigned int            idr_base;
    unsigned int            idr_next;
};

/**
 * idr_init_base() - Initialise an IDR.
 * @idr: IDR handle.
 * @base: The base value for the IDR.
 *
 * This variation of idr_init() creates an IDR which will allocate IDs
 * starting at %base.
 */
static inline void idr_init_base(struct idr *idr, int base)
{
    INIT_RADIX_TREE(&idr->idr_rt, IDR_RT_MARKER);
    idr->idr_base = base;
    idr->idr_next = 0;
}

/**
 * idr_get_cursor - Return the current position of the cyclic allocator
 * @idr: idr handle
 *
 * The value returned is the value that will be next returned from
 * idr_alloc_cyclic() if it is free (otherwise the search will start from
 * this position).
 */
static inline unsigned int idr_get_cursor(const struct idr *idr)
{
    return READ_ONCE(idr->idr_next);
}

int idr_alloc_cyclic(struct idr *, void *ptr, int start, int end, gfp_t);

/**
 * idr_init() - Initialise an IDR.
 * @idr: IDR handle.
 *
 * Initialise a dynamically allocated IDR.  To initialise a
 * statically allocated IDR, use DEFINE_IDR().
 */
static inline void idr_init(struct idr *idr)
{
    idr_init_base(idr, 0);
}

#endif /* __IDR_H__ */
