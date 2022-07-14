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
#include <linux/lockdep.h>
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

#define RADIX_TREE(name, mask) \
    struct radix_tree_root name = RADIX_TREE_INIT(name, mask)

/*
 * The bottom two bits of the slot determine how the remaining bits in the
 * slot are interpreted:
 *
 * 00 - data pointer
 * 10 - internal entry
 * x1 - value entry
 *
 * The internal entry may be a pointer to the next level in the tree, a
 * sibling entry, or an indicator that the entry in this slot has been moved
 * to another location in the tree and the lookup should be restarted.  While
 * NULL fits the 'data pointer' pattern, it means that there is no entry in
 * the tree for this index (no matter what level of the tree it is found at).
 * This means that storing a NULL entry in the tree is the same as deleting
 * the entry from the tree.
 */
#define RADIX_TREE_ENTRY_MASK       3UL
#define RADIX_TREE_INTERNAL_NODE    2UL

static inline bool radix_tree_is_internal_node(void *ptr)
{
    return ((unsigned long)ptr & RADIX_TREE_ENTRY_MASK) ==
        RADIX_TREE_INTERNAL_NODE;
}

/**
 * struct radix_tree_iter - radix tree iterator state
 *
 * @index:  index of current slot
 * @next_index: one beyond the last index for this chunk
 * @tags:   bit-mask for tag-iterating
 * @node:   node that contains current slot
 *
 * This radix tree iterator works in terms of "chunks" of slots.  A chunk is a
 * subinterval of slots contained within one radix tree leaf node.  It is
 * described by a pointer to its first slot and a struct radix_tree_iter
 * which holds the chunk's position in the tree and its size.  For tagged
 * iteration radix_tree_iter also holds the slots' bit-mask for one chosen
 * radix tree tag.
 */
struct radix_tree_iter {
    unsigned long   index;
    unsigned long   next_index;
    unsigned long   tags;
    struct radix_tree_node *node;
};

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

#define RADIX_TREE_MAX_TAGS     XA_MAX_MARKS
#define RADIX_TREE_TAG_LONGS    XA_MARK_LONGS

#define RADIX_TREE_MAP_SHIFT    XA_CHUNK_SHIFT
#define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK     (RADIX_TREE_MAP_SIZE-1)

/**
 * radix_tree_iter_init - initialize radix tree iterator
 *
 * @iter:   pointer to iterator state
 * @start:  iteration starting index
 * Returns: NULL
 */
static __always_inline void __rcu **
radix_tree_iter_init(struct radix_tree_iter *iter, unsigned long start)
{
    /*
     * Leave iter->tags uninitialized. radix_tree_next_chunk() will fill it
     * in the case of a successful tagged chunk lookup.  If the lookup was
     * unsuccessful or non-tagged then nobody cares about ->tags.
     *
     * Set index to zero to bypass next_index overflow protection.
     * See the comment in radix_tree_next_chunk() for details.
     */
    iter->index = 0;
    iter->next_index = start;
    return NULL;
}

void __rcu **
idr_get_free(struct radix_tree_root *root,
             struct radix_tree_iter *iter, gfp_t gfp, unsigned long max);

void radix_tree_iter_replace(struct radix_tree_root *,
                             const struct radix_tree_iter *,
                             void __rcu **slot, void *entry);

void *radix_tree_tag_set(struct radix_tree_root *,
                         unsigned long index, unsigned int tag);
void *radix_tree_tag_clear(struct radix_tree_root *,
                           unsigned long index, unsigned int tag);

void radix_tree_iter_tag_clear(struct radix_tree_root *,
                               const struct radix_tree_iter *iter,
                               unsigned int tag);

void *radix_tree_delete_item(struct radix_tree_root *, unsigned long, void *);

static inline unsigned long
__radix_tree_iter_add(struct radix_tree_iter *iter, unsigned long slots)
{
    return iter->index + slots;
}

void *__radix_tree_lookup(const struct radix_tree_root *, unsigned long index,
                          struct radix_tree_node **nodep, void __rcu ***slotp);

void __radix_tree_replace(struct radix_tree_root *, struct radix_tree_node *,
                          void __rcu **slot, void *entry);

int radix_tree_tag_get(const struct radix_tree_root *,
                       unsigned long index, unsigned int tag);

void *radix_tree_lookup(const struct radix_tree_root *, unsigned long);

int radix_tree_insert(struct radix_tree_root *, unsigned long index, void *);

void *radix_tree_delete_item(struct radix_tree_root *, unsigned long, void *);
void *radix_tree_delete(struct radix_tree_root *, unsigned long);

#endif /* _LINUX_RADIX_TREE_H */
