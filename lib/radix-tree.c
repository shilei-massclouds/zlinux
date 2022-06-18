// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2005 SGI, Christoph Lameter
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2012 Konstantin Khlebnikov
 * Copyright (C) 2016 Intel, Matthew Wilcox
 * Copyright (C) 2016 Intel, Ross Zwisler
 */

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/preempt.h>      /* in_interrupt() */
#include <linux/radix-tree.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xarray.h>

/*
 * The IDR does not have to be as high as the radix tree since it uses
 * signed integers, not unsigned longs.
 */
#define IDR_INDEX_BITS      (8 /* CHAR_BIT */ * sizeof(int) - 1)
#define IDR_MAX_PATH        (DIV_ROUND_UP(IDR_INDEX_BITS, RADIX_TREE_MAP_SHIFT))

#define IDR_PRELOAD_SIZE    (IDR_MAX_PATH * 2 - 1)

/*
 * Radix tree node cache.
 */
struct kmem_cache *radix_tree_node_cachep;

/*
 * Per-cpu pool of preloaded nodes
 */
DEFINE_PER_CPU(struct radix_tree_preload, radix_tree_preloads) = {
    .lock = INIT_LOCAL_LOCK(lock),
};
EXPORT_PER_CPU_SYMBOL_GPL(radix_tree_preloads);

/*
 * Load up this CPU's radix_tree_node buffer with sufficient objects to
 * ensure that the addition of a single element in the tree cannot fail.  On
 * success, return zero, with preemption disabled.  On error, return -ENOMEM
 * with preemption not disabled.
 *
 * To make use of this facility, the radix tree must be initialised without
 * __GFP_DIRECT_RECLAIM being passed to INIT_RADIX_TREE().
 */
static __must_check int __radix_tree_preload(gfp_t gfp_mask, unsigned nr)
{
    struct radix_tree_preload *rtp;
    struct radix_tree_node *node;
    int ret = -ENOMEM;

    /*
     * Nodes preloaded by one cgroup can be used by another cgroup, so
     * they should never be accounted to any particular memory cgroup.
     */
    gfp_mask &= ~__GFP_ACCOUNT;

    local_lock(&radix_tree_preloads.lock);
    rtp = this_cpu_ptr(&radix_tree_preloads);
    while (rtp->nr < nr) {
        local_unlock(&radix_tree_preloads.lock);
        node = kmem_cache_alloc(radix_tree_node_cachep, gfp_mask);
        if (node == NULL)
            goto out;
        local_lock(&radix_tree_preloads.lock);
        rtp = this_cpu_ptr(&radix_tree_preloads);
        if (rtp->nr < nr) {
            node->parent = rtp->nodes;
            rtp->nodes = node;
            rtp->nr++;
        } else {
            kmem_cache_free(radix_tree_node_cachep, node);
        }
    }
    ret = 0;
out:
    return ret;
}

/**
 * idr_preload - preload for idr_alloc()
 * @gfp_mask: allocation mask to use for preloading
 *
 * Preallocate memory to use for the next call to idr_alloc().  This function
 * returns with preemption disabled.  It will be enabled by idr_preload_end().
 */
void idr_preload(gfp_t gfp_mask)
{
    if (__radix_tree_preload(gfp_mask, IDR_PRELOAD_SIZE))
        local_lock(&radix_tree_preloads.lock);
}
EXPORT_SYMBOL(idr_preload);

static void
radix_tree_node_ctor(void *arg)
{
    struct radix_tree_node *node = arg;

    memset(node, 0, sizeof(*node));
    INIT_LIST_HEAD(&node->private_list);
}

void __init radix_tree_init(void)
{
    int ret;

    BUILD_BUG_ON(RADIX_TREE_MAX_TAGS + __GFP_BITS_SHIFT > 32);
    BUILD_BUG_ON(ROOT_IS_IDR & ~GFP_ZONEMASK);
    BUILD_BUG_ON(XA_CHUNK_SIZE > 255);
    radix_tree_node_cachep =
        kmem_cache_create("radix_tree_node", sizeof(struct radix_tree_node), 0,
                          SLAB_PANIC | SLAB_RECLAIM_ACCOUNT,
                          radix_tree_node_ctor);
#if 0
    ret = cpuhp_setup_state_nocalls(CPUHP_RADIX_DEAD, "lib/radix:dead",
                                    NULL, radix_tree_cpu_dead);
    WARN_ON(ret < 0);
#endif
}
