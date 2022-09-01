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

#define WORKINGSET_SHIFT 1
#define EVICTION_SHIFT  ((BITS_PER_LONG - BITS_PER_XA_VALUE) +  \
                         WORKINGSET_SHIFT + NODES_SHIFT + \
                         MEM_CGROUP_ID_SHIFT)
#define EVICTION_MASK   (~0UL >> EVICTION_SHIFT)

/*
 * Eviction timestamps need to be able to cover the full range of
 * actionable refaults. However, bits are tight in the xarray
 * entry, and after storing the identifier for the lruvec there might
 * not be enough left to represent every single actionable refault. In
 * that case, we have to sacrifice granularity for distance, and group
 * evictions into coarser buckets by shaving off lower timestamp bits.
 */
static unsigned int bucket_order __read_mostly;

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

static void *pack_shadow(int memcgid, pg_data_t *pgdat, unsigned long eviction,
                         bool workingset)
{
    eviction >>= bucket_order;
    eviction &= EVICTION_MASK;
    eviction = (eviction << MEM_CGROUP_ID_SHIFT) | memcgid;
    eviction = (eviction << NODES_SHIFT) | pgdat->node_id;
    eviction = (eviction << WORKINGSET_SHIFT) | workingset;

    return xa_mk_value(eviction);
}

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

/**
 * workingset_age_nonresident - age non-resident entries as LRU ages
 * @lruvec: the lruvec that was aged
 * @nr_pages: the number of pages to count
 *
 * As in-memory pages are aged, non-resident pages need to be aged as
 * well, in order for the refault distances later on to be comparable
 * to the in-memory dimensions. This function allows reclaim and LRU
 * operations to drive the non-resident aging along in parallel.
 */
void workingset_age_nonresident(struct lruvec *lruvec, unsigned long nr_pages)
{
    /*
     * Reclaiming a cgroup means reclaiming all its children in a
     * round-robin fashion. That means that each cgroup has an LRU
     * order that is composed of the LRU orders of its child
     * cgroups; and every page has an LRU position not just in the
     * cgroup that owns it, but in all of that group's ancestors.
     *
     * So when the physical inactive list of a leaf cgroup ages,
     * the virtual inactive lists of all its parents, including
     * the root cgroup's, age as well.
     */
    do {
        atomic_long_add(nr_pages, &lruvec->nonresident_age);
    } while ((lruvec = parent_lruvec(lruvec)));
}

/**
 * workingset_eviction - note the eviction of a folio from memory
 * @target_memcg: the cgroup that is causing the reclaim
 * @folio: the folio being evicted
 *
 * Return: a shadow entry to be stored in @folio->mapping->i_pages in place
 * of the evicted @folio so that a later refault can be detected.
 */
void *workingset_eviction(struct folio *folio, struct mem_cgroup *target_memcg)
{
    struct pglist_data *pgdat = folio_pgdat(folio);
    unsigned long eviction;
    struct lruvec *lruvec;
    int memcgid;

    /* Folio is fully exclusive and pins folio's memory cgroup pointer */
    VM_BUG_ON_FOLIO(folio_test_lru(folio), folio);
    VM_BUG_ON_FOLIO(folio_ref_count(folio), folio);
    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

    lruvec = mem_cgroup_lruvec(target_memcg, pgdat);
    /* XXX: target_memcg can be NULL, go through lruvec */
    memcgid = 0;
    eviction = atomic_long_read(&lruvec->nonresident_age);
    workingset_age_nonresident(lruvec, folio_nr_pages(folio));
    return pack_shadow(memcgid, pgdat, eviction, folio_test_workingset(folio));
}

static unsigned long count_shadow_nodes(struct shrinker *shrinker,
                                        struct shrink_control *sc)
{
    unsigned long max_nodes;
    unsigned long nodes;
    unsigned long pages;

    panic("%s: END!\n", __func__);
}

static unsigned long scan_shadow_nodes(struct shrinker *shrinker,
                                       struct shrink_control *sc)
{
    /* list_lru lock nests inside the IRQ-safe i_pages lock */
#if 0
    return list_lru_shrink_walk_irq(&shadow_nodes, sc, shadow_lru_isolate,
                                    NULL);
#endif
    panic("%s: END!\n", __func__);
}

static struct shrinker workingset_shadow_shrinker = {
    .count_objects = count_shadow_nodes,
    .scan_objects = scan_shadow_nodes,
    .seeks = 0, /* ->count reports only fully expendable nodes */
    .flags = SHRINKER_NUMA_AWARE | SHRINKER_MEMCG_AWARE,
};

/*
 * Add a shrinker callback to be called from the vm.
 */
int prealloc_shrinker(struct shrinker *shrinker)
{
    unsigned int size;
    int err;

    if (shrinker->flags & SHRINKER_MEMCG_AWARE) {
        shrinker->flags &= ~SHRINKER_MEMCG_AWARE;
    }

    size = sizeof(*shrinker->nr_deferred);
    if (shrinker->flags & SHRINKER_NUMA_AWARE)
        size *= nr_node_ids;

    shrinker->nr_deferred = kzalloc(size, GFP_KERNEL);
    if (!shrinker->nr_deferred)
        return -ENOMEM;

    return 0;
}

static struct lock_class_key shadow_nodes_key;

static int __init workingset_init(void)
{
    unsigned int timestamp_bits;
    unsigned int max_order;
    int ret;

    BUILD_BUG_ON(BITS_PER_LONG < EVICTION_SHIFT);
    /*
     * Calculate the eviction bucket size to cover the longest
     * actionable refault distance, which is currently half of
     * memory (totalram_pages/2). However, memory hotplug may add
     * some more pages at runtime, so keep working with up to
     * double the initial memory by using totalram_pages as-is.
     */
    timestamp_bits = BITS_PER_LONG - EVICTION_SHIFT;
    max_order = fls_long(totalram_pages() - 1);
    if (max_order > timestamp_bits)
        bucket_order = max_order - timestamp_bits;
    pr_info("workingset: timestamp_bits=%d max_order=%d bucket_order=%u\n",
            timestamp_bits, max_order, bucket_order);

    ret = prealloc_shrinker(&workingset_shadow_shrinker);
    if (ret)
        goto err;
    ret = __list_lru_init(&shadow_nodes, true, &shadow_nodes_key,
                          &workingset_shadow_shrinker);
    if (ret)
        goto err_list_lru;
    register_shrinker_prepared(&workingset_shadow_shrinker);
    return 0;
 err_list_lru:
    free_prealloced_shrinker(&workingset_shadow_shrinker);
 err:
    return ret;
}
module_init(workingset_init);
