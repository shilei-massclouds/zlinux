/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2012 Konstantin Khlebnikov
 */
#ifndef _LINUX_RADIX_TREE_H
#define _LINUX_RADIX_TREE_H

#include <linux/bitops.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/math.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/xarray.h>
#include <linux/local_lock.h>

/* Keep unconverted code working */
#define radix_tree_root     xarray
#define radix_tree_node     xa_node

struct radix_tree_preload {
    local_lock_t lock;
    unsigned nr;
    /* nodes->parent points to next preallocated node */
    struct radix_tree_node *nodes;
};
DECLARE_PER_CPU(struct radix_tree_preload, radix_tree_preloads);

/* The IDR tag is stored in the low bits of xa_flags */
#define ROOT_IS_IDR     ((__force gfp_t)4)
/* The top bits of xa_flags are used to store the root tags */
#define ROOT_TAG_SHIFT  (__GFP_BITS_SHIFT)

#define INIT_RADIX_TREE(root, mask) xa_init_flags(root, mask)

#define RADIX_TREE_INIT(name, mask) XARRAY_INIT(name, mask)

#define RADIX_TREE_MAX_TAGS XA_MAX_MARKS

#define RADIX_TREE_MAP_SHIFT    XA_CHUNK_SHIFT
#define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK     (RADIX_TREE_MAP_SIZE-1)

#endif /* _LINUX_RADIX_TREE_H */
