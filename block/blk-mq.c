// SPDX-License-Identifier: GPL-2.0
/*
 * Block multiqueue core code
 *
 * Copyright (C) 2013-2014 Jens Axboe
 * Copyright (C) 2013-2014 Christoph Hellwig
 */
#include <linux/kernel.h>
#include <linux/module.h>
//#include <linux/backing-dev.h>
//#include <linux/bio.h>
#include <linux/blkdev.h>
#if 0
#include <linux/blk-integrity.h>
#include <linux/kmemleak.h>
#endif
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
//#include <linux/workqueue.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/llist.h>
#include <linux/cpu.h>
#include <linux/cache.h>
//#include <linux/sched/sysctl.h>
#include <linux/sched/topology.h>
#include <linux/sched/signal.h>
#if 0
#include <linux/delay.h>
#include <linux/crash_dump.h>
#include <linux/blk-crypto.h>
#include <linux/part_stat.h>
#endif
#include <linux/prefetch.h>

#include <linux/blk-mq.h>
#include "blk-mq.h"
#if 0
#include <linux/t10-pi.h>
#include "blk.h"
#include "blk-mq-debugfs.h"
#include "blk-pm.h"
#include "blk-stat.h"
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"
#endif
#include "blk-mq-tag.h"

static int blk_mq_realloc_tag_set_tags(struct blk_mq_tag_set *set,
                                       int cur_nr_hw_queues,
                                       int new_nr_hw_queues)
{
    struct blk_mq_tags **new_tags;

    if (cur_nr_hw_queues >= new_nr_hw_queues)
        return 0;

    new_tags = kcalloc_node(new_nr_hw_queues, sizeof(struct blk_mq_tags *),
                            GFP_KERNEL, set->numa_node);
    if (!new_tags)
        return -ENOMEM;

    if (set->tags)
        memcpy(new_tags, set->tags, cur_nr_hw_queues * sizeof(*set->tags));
    kfree(set->tags);
    set->tags = new_tags;
    set->nr_hw_queues = new_nr_hw_queues;

    return 0;
}

static int blk_mq_alloc_tag_set_tags(struct blk_mq_tag_set *set,
                                     int new_nr_hw_queues)
{
    return blk_mq_realloc_tag_set_tags(set, 0, new_nr_hw_queues);
}

static int blk_mq_update_queue_map(struct blk_mq_tag_set *set)
{
    /*
     * blk_mq_map_queues() and multiple .map_queues() implementations
     * expect that set->map[HCTX_TYPE_DEFAULT].nr_queues is set to the
     * number of hardware queues.
     */
    if (set->nr_maps == 1)
        set->map[HCTX_TYPE_DEFAULT].nr_queues = set->nr_hw_queues;

    if (set->ops->map_queues) {
        int i;

        /*
         * transport .map_queues is usually done in the following
         * way:
         *
         * for (queue = 0; queue < set->nr_hw_queues; queue++) {
         *  mask = get_cpu_mask(queue)
         *  for_each_cpu(cpu, mask)
         *      set->map[x].mq_map[cpu] = queue;
         * }
         *
         * When we need to remap, the table has to be cleared for
         * killing stale mapping since one CPU may not be mapped
         * to any hw queue.
         */
        for (i = 0; i < set->nr_maps; i++)
            blk_mq_clear_mq_map(&set->map[i]);

        return set->ops->map_queues(set);
    } else {
        panic("%s: map_queues\n", __func__);
#if 0
        BUG_ON(set->nr_maps > 1);
        return blk_mq_map_queues(&set->map[HCTX_TYPE_DEFAULT]);
#endif
    }
}

static enum hctx_type hctx_idx_to_type(struct blk_mq_tag_set *set,
                                       unsigned int hctx_idx)
{
    int i;

    for (i = 0; i < set->nr_maps; i++) {
        unsigned int start = set->map[i].queue_offset;
        unsigned int end = start + set->map[i].nr_queues;

        if (hctx_idx >= start && hctx_idx < end)
            break;
    }

    if (i >= set->nr_maps)
        i = HCTX_TYPE_DEFAULT;

    return i;
}

static int blk_mq_get_hctx_node(struct blk_mq_tag_set *set,
                                unsigned int hctx_idx)
{
    enum hctx_type type = hctx_idx_to_type(set, hctx_idx);

    return blk_mq_hw_queue_to_node(&set->map[type], hctx_idx);
}

static struct blk_mq_tags *
blk_mq_alloc_rq_map(struct blk_mq_tag_set *set,
                    unsigned int hctx_idx,
                    unsigned int nr_tags,
                    unsigned int reserved_tags)
{
    int node = blk_mq_get_hctx_node(set, hctx_idx);
    struct blk_mq_tags *tags;

    if (node == NUMA_NO_NODE)
        node = set->numa_node;

    tags = blk_mq_init_tags(nr_tags, reserved_tags, node,
                            BLK_MQ_FLAG_TO_ALLOC_POLICY(set->flags));
    if (!tags)
        return NULL;

    tags->rqs = kcalloc_node(nr_tags, sizeof(struct request *),
                             GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
                             node);
    if (!tags->rqs) {
        blk_mq_free_tags(tags);
        return NULL;
    }

    tags->static_rqs = kcalloc_node(nr_tags, sizeof(struct request *),
                    GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
                    node);
    if (!tags->static_rqs) {
        kfree(tags->rqs);
        blk_mq_free_tags(tags);
        return NULL;
    }

    return tags;
}

static int blk_mq_alloc_rqs(struct blk_mq_tag_set *set,
                            struct blk_mq_tags *tags,
                            unsigned int hctx_idx, unsigned int depth)
{
    panic("%s: END!\n", __func__);
}

struct blk_mq_tags *blk_mq_alloc_map_and_rqs(struct blk_mq_tag_set *set,
                                             unsigned int hctx_idx,
                                             unsigned int depth)
{
    struct blk_mq_tags *tags;
    int ret;

    tags = blk_mq_alloc_rq_map(set, hctx_idx, depth, set->reserved_tags);
    if (!tags)
        return NULL;

    ret = blk_mq_alloc_rqs(set, tags, hctx_idx, depth);
    if (ret) {
        blk_mq_free_rq_map(tags);
        return NULL;
    }

    return tags;
}

static bool __blk_mq_alloc_map_and_rqs(struct blk_mq_tag_set *set, int hctx_idx)
{
    if (blk_mq_is_shared_tags(set->flags)) {
        set->tags[hctx_idx] = set->shared_tags;

        return true;
    }

    set->tags[hctx_idx] = blk_mq_alloc_map_and_rqs(set, hctx_idx,
                                                   set->queue_depth);

    return set->tags[hctx_idx];
}

static int __blk_mq_alloc_rq_maps(struct blk_mq_tag_set *set)
{
    int i;

    if (blk_mq_is_shared_tags(set->flags)) {
        set->shared_tags = blk_mq_alloc_map_and_rqs(set, BLK_MQ_NO_HCTX_IDX,
                                                    set->queue_depth);
        if (!set->shared_tags)
            return -ENOMEM;
    }

    for (i = 0; i < set->nr_hw_queues; i++) {
        if (!__blk_mq_alloc_map_and_rqs(set, i))
            goto out_unwind;
        cond_resched();
    }

    return 0;

out_unwind:
    panic("%s: END!\n", __func__);
#if 0
    while (--i >= 0)
        __blk_mq_free_map_and_rqs(set, i);

    if (blk_mq_is_shared_tags(set->flags)) {
        blk_mq_free_map_and_rqs(set, set->shared_tags, BLK_MQ_NO_HCTX_IDX);
    }
#endif

    return -ENOMEM;
}

void blk_mq_free_map_and_rqs(struct blk_mq_tag_set *set,
                             struct blk_mq_tags *tags,
                             unsigned int hctx_idx)
{
#if 0
    if (tags) {
        blk_mq_free_rqs(set, tags, hctx_idx);
        blk_mq_free_rq_map(tags);
    }
#endif
    panic("%s: END!\n", __func__);
}

/*
 * Allocate the request maps associated with this tag_set. Note that this
 * may reduce the depth asked for, if memory is tight. set->queue_depth
 * will be updated to reflect the allocated depth.
 */
static int blk_mq_alloc_set_map_and_rqs(struct blk_mq_tag_set *set)
{
    unsigned int depth;
    int err;

    depth = set->queue_depth;
    do {
        err = __blk_mq_alloc_rq_maps(set);
        if (!err)
            break;

        set->queue_depth >>= 1;
        if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN) {
            err = -ENOMEM;
            break;
        }
    } while (set->queue_depth);

    if (!set->queue_depth || err) {
        pr_err("blk-mq: failed to allocate request map\n");
        return -ENOMEM;
    }

    if (depth != set->queue_depth)
        pr_info("blk-mq: reduced tag depth (%u -> %u)\n",
                        depth, set->queue_depth);

    return 0;
}

void blk_mq_free_rq_map(struct blk_mq_tags *tags)
{
    kfree(tags->rqs);
    tags->rqs = NULL;
    kfree(tags->static_rqs);
    tags->static_rqs = NULL;

    blk_mq_free_tags(tags);
}

/*
 * Alloc a tag set to be associated with one or more request queues.
 * May fail with EINVAL for various error conditions. May adjust the
 * requested depth down, if it's too large. In that case, the set
 * value will be stored in set->queue_depth.
 */
int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set)
{
    int i, ret;

    BUILD_BUG_ON(BLK_MQ_MAX_DEPTH > 1 << BLK_MQ_UNIQUE_TAG_BITS);

    if (!set->nr_hw_queues)
        return -EINVAL;
    if (!set->queue_depth)
        return -EINVAL;
    if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN)
        return -EINVAL;

    if (!set->ops->queue_rq)
        return -EINVAL;

    if (!set->ops->get_budget ^ !set->ops->put_budget)
        return -EINVAL;

    if (set->queue_depth > BLK_MQ_MAX_DEPTH) {
        pr_info("blk-mq: reduced tag depth to %u\n", BLK_MQ_MAX_DEPTH);
        set->queue_depth = BLK_MQ_MAX_DEPTH;
    }

    if (!set->nr_maps)
        set->nr_maps = 1;
    else if (set->nr_maps > HCTX_MAX_TYPES)
        return -EINVAL;

    /*
     * There is no use for more h/w queues than cpus if we just have
     * a single map
     */
    if (set->nr_maps == 1 && set->nr_hw_queues > nr_cpu_ids)
        set->nr_hw_queues = nr_cpu_ids;

    if (blk_mq_alloc_tag_set_tags(set, set->nr_hw_queues) < 0)
        return -ENOMEM;

    ret = -ENOMEM;
    for (i = 0; i < set->nr_maps; i++) {
        set->map[i].mq_map = kcalloc_node(nr_cpu_ids,
                                          sizeof(set->map[i].mq_map[0]),
                                          GFP_KERNEL, set->numa_node);
        if (!set->map[i].mq_map)
            goto out_free_mq_map;
        set->map[i].nr_queues = set->nr_hw_queues;
    }

    ret = blk_mq_update_queue_map(set);
    if (ret)
        goto out_free_mq_map;

    ret = blk_mq_alloc_set_map_and_rqs(set);
    if (ret)
        goto out_free_mq_map;

    panic("%s: END!\n", __func__);
    return 0;

 out_free_mq_map:
    for (i = 0; i < set->nr_maps; i++) {
        kfree(set->map[i].mq_map);
        set->map[i].mq_map = NULL;
    }
    kfree(set->tags);
    set->tags = NULL;
    return ret;
}
