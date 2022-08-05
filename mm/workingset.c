// SPDX-License-Identifier: GPL-2.0
/*
 * Workingset detection
 *
 * Copyright (C) 2013 Red Hat, Inc., Johannes Weiner
 */

#include <linux/memcontrol.h>
//#include <linux/mm_inline.h>
#include <linux/writeback.h>
#include <linux/shmem_fs.h>
#include <linux/pagemap.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/swap.h>
//#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/mm.h>

/*
 * Shadow entries reflect the share of the working set that does not
 * fit into memory, so their number depends on the access pattern of
 * the workload.  In most cases, they will refault or get reclaimed
 * along with the inode, but a (malicious) workload that streams
 * through files with a total size several times that of available
 * memory, while preventing the inodes from being reclaimed, can
 * create excessive amounts of shadow nodes.  To keep a lid on this,
 * track shadow nodes and reclaim them when they grow way past the
 * point where they would still be useful.
 */

struct list_lru shadow_nodes;

void workingset_update_node(struct xa_node *node)
{
    struct address_space *mapping;

    /*
     * Track non-empty nodes that contain only shadow entries;
     * unlink those that contain pages or are being freed.
     *
     * Avoid acquiring the list_lru lock when the nodes are
     * already where they should be. The list_empty() test is safe
     * as node->private_list is protected by the i_pages lock.
     */
    mapping = container_of(node->array, struct address_space, i_pages);

    if (node->count && node->count == node->nr_values) {
        if (list_empty(&node->private_list)) {
            list_lru_add(&shadow_nodes, &node->private_list);
            __inc_lruvec_kmem_state(node, WORKINGSET_NODES);
        }
    } else {
        if (!list_empty(&node->private_list)) {
            list_lru_del(&shadow_nodes, &node->private_list);
            __dec_lruvec_kmem_state(node, WORKINGSET_NODES);
        }
    }
}

/**
 * workingset_refault - Evaluate the refault of a previously evicted folio.
 * @folio: The freshly allocated replacement folio.
 * @shadow: Shadow entry of the evicted folio.
 *
 * Calculates and evaluates the refault distance of the previously
 * evicted folio in the context of the node and the memcg whose memory
 * pressure caused the eviction.
 */
void workingset_refault(struct folio *folio, void *shadow)
{
    panic("%s: END!\n", __func__);
}
