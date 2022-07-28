// SPDX-License-Identifier: GPL-2.0
/*
 * Block multiqueue core code
 *
 * Copyright (C) 2013-2014 Jens Axboe
 * Copyright (C) 2013-2014 Christoph Hellwig
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#if 0
#include <linux/blk-integrity.h>
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
#include <linux/sched/topology.h>
#include <linux/sched/signal.h>
#if 0
#include <linux/sched/sysctl.h>
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
#include "blk-mq-debugfs.h"
#include "blk-pm.h"
#include "blk-stat.h"
#include "blk-rq-qos.h"
#endif
#include "blk-mq-sched.h"
#include "blk.h"
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

static int blk_mq_init_request(struct blk_mq_tag_set *set, struct request *rq,
                   unsigned int hctx_idx, int node)
{
    int ret;

    if (set->ops->init_request) {
        ret = set->ops->init_request(set, rq, hctx_idx, node);
        if (ret)
            return ret;
    }

    WRITE_ONCE(rq->state, MQ_RQ_IDLE);
    return 0;
}

void blk_mq_free_rqs(struct blk_mq_tag_set *set, struct blk_mq_tags *tags,
                     unsigned int hctx_idx)
{
    panic("%s: END!\n", __func__);
}

static size_t order_to_size(unsigned int order)
{
    return (size_t)PAGE_SIZE << order;
}

static int blk_mq_alloc_rqs(struct blk_mq_tag_set *set,
                            struct blk_mq_tags *tags,
                            unsigned int hctx_idx, unsigned int depth)
{
    unsigned int i, j, entries_per_page, max_order = 4;
    int node = blk_mq_get_hctx_node(set, hctx_idx);
    size_t rq_size, left;

    if (node == NUMA_NO_NODE)
        node = set->numa_node;

    INIT_LIST_HEAD(&tags->page_list);

    /*
     * rq_size is the size of the request plus driver payload, rounded
     * to the cacheline size
     */
    rq_size = round_up(sizeof(struct request) + set->cmd_size,
                       cache_line_size());
    left = rq_size * depth;

    for (i = 0; i < depth; ) {
        int this_order = max_order;
        struct page *page;
        int to_do;
        void *p;

        while (this_order && left < order_to_size(this_order - 1))
            this_order--;

        do {
            page = alloc_pages_node(node,
                                    GFP_NOIO | __GFP_NOWARN |
                                    __GFP_NORETRY | __GFP_ZERO,
                                    this_order);
            if (page)
                break;
            if (!this_order--)
                break;
            if (order_to_size(this_order) < rq_size)
                break;
        } while (1);

        if (!page)
            goto fail;

        page->private = this_order;
        list_add_tail(&page->lru, &tags->page_list);

        p = page_address(page);
        /*
         * Allow kmemleak to scan these pages as they contain pointers
         * to additional allocations like via ops->init_request().
         */
        entries_per_page = order_to_size(this_order) / rq_size;
        to_do = min(entries_per_page, depth - i);
        left -= to_do * rq_size;
        for (j = 0; j < to_do; j++) {
            struct request *rq = p;

            tags->static_rqs[i] = rq;
            if (blk_mq_init_request(set, rq, hctx_idx, node)) {
                tags->static_rqs[i] = NULL;
                goto fail;
            }

            p += rq_size;
            i++;
        }
    }

    return 0;

 fail:
    blk_mq_free_rqs(set, tags, hctx_idx);
    return -ENOMEM;
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

    mutex_init(&set->tag_list_lock);
    INIT_LIST_HEAD(&set->tag_list);

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

static void blk_mq_update_poll_flag(struct request_queue *q)
{
    struct blk_mq_tag_set *set = q->tag_set;

    if (set->nr_maps > HCTX_TYPE_POLL && set->map[HCTX_TYPE_POLL].nr_queues)
        blk_queue_flag_set(QUEUE_FLAG_POLL, q);
    else
        blk_queue_flag_clear(QUEUE_FLAG_POLL, q);
}

/* All allocations will be freed in release handler of q->mq_kobj */
static int blk_mq_alloc_ctxs(struct request_queue *q)
{
    struct blk_mq_ctxs *ctxs;
    int cpu;

    ctxs = kzalloc(sizeof(*ctxs), GFP_KERNEL);
    if (!ctxs)
        return -ENOMEM;

    ctxs->queue_ctx = alloc_percpu(struct blk_mq_ctx);
    if (!ctxs->queue_ctx)
        goto fail;

    for_each_possible_cpu(cpu) {
        struct blk_mq_ctx *ctx = per_cpu_ptr(ctxs->queue_ctx, cpu);
        ctx->ctxs = ctxs;
    }

    q->mq_kobj = &ctxs->kobj;
    q->queue_ctx = ctxs->queue_ctx;

    return 0;
 fail:
    kfree(ctxs);
    return -ENOMEM;
}

/* hctx->ctxs will be freed in queue's release handler */
static void blk_mq_exit_hctx(struct request_queue *q,
                             struct blk_mq_tag_set *set,
                             struct blk_mq_hw_ctx *hctx,
                             unsigned int hctx_idx)
{
    panic("%s: END!\n", __func__);
}

static struct blk_mq_hw_ctx *
blk_mq_alloc_hctx(struct request_queue *q, struct blk_mq_tag_set *set, int node)
{
    struct blk_mq_hw_ctx *hctx;
    gfp_t gfp = GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY;

    hctx = kzalloc_node(sizeof(struct blk_mq_hw_ctx), gfp, node);
    if (!hctx)
        goto fail_alloc_hctx;

    if (!zalloc_cpumask_var_node(&hctx->cpumask, gfp, node))
        goto free_hctx;

    atomic_set(&hctx->nr_active, 0);
    if (node == NUMA_NO_NODE)
        node = set->numa_node;
    hctx->numa_node = node;

#if 0
    INIT_DELAYED_WORK(&hctx->run_work, blk_mq_run_work_fn);
#endif
    spin_lock_init(&hctx->lock);
    INIT_LIST_HEAD(&hctx->dispatch);
    hctx->queue = q;
    hctx->flags = set->flags & ~BLK_MQ_F_TAG_QUEUE_SHARED;

    INIT_LIST_HEAD(&hctx->hctx_list);

    /*
     * Allocate space for all possible cpus to avoid allocation at
     * runtime
     */
    hctx->ctxs = kmalloc_array_node(nr_cpu_ids, sizeof(void *), gfp, node);
    if (!hctx->ctxs)
        goto free_cpumask;

    if (sbitmap_init_node(&hctx->ctx_map, nr_cpu_ids, ilog2(8),
                          gfp, node, false, false))
        goto free_ctxs;
    hctx->nr_ctx = 0;

    spin_lock_init(&hctx->dispatch_wait_lock);
#if 0
    init_waitqueue_func_entry(&hctx->dispatch_wait, blk_mq_dispatch_wake);
    INIT_LIST_HEAD(&hctx->dispatch_wait.entry);
#endif

    hctx->fq = blk_alloc_flush_queue(hctx->numa_node, set->cmd_size, gfp);
    if (!hctx->fq)
        goto free_bitmap;

    blk_mq_hctx_kobj_init(hctx);

    return hctx;

 free_bitmap:
    sbitmap_free(&hctx->ctx_map);
 free_ctxs:
    kfree(hctx->ctxs);
 free_cpumask:
    free_cpumask_var(hctx->cpumask);
 free_hctx:
    kfree(hctx);
 fail_alloc_hctx:
    return NULL;
}

static int blk_mq_init_hctx(struct request_queue *q,
                            struct blk_mq_tag_set *set,
                            struct blk_mq_hw_ctx *hctx,
                            unsigned hctx_idx)
{
    hctx->queue_num = hctx_idx;

#if 0
    if (!(hctx->flags & BLK_MQ_F_STACKING))
        cpuhp_state_add_instance_nocalls(CPUHP_AP_BLK_MQ_ONLINE,
                &hctx->cpuhp_online);
    cpuhp_state_add_instance_nocalls(CPUHP_BLK_MQ_DEAD, &hctx->cpuhp_dead);
#endif

    hctx->tags = set->tags[hctx_idx];

    if (set->ops->init_hctx &&
        set->ops->init_hctx(hctx, set->driver_data, hctx_idx))
        goto unregister_cpu_notifier;

    if (blk_mq_init_request(set, hctx->fq->flush_rq, hctx_idx, hctx->numa_node))
        goto exit_hctx;

    if (xa_insert(&q->hctx_table, hctx_idx, hctx, GFP_KERNEL))
        goto exit_flush_rq;

    return 0;

 exit_flush_rq:
    if (set->ops->exit_request)
        set->ops->exit_request(set, hctx->fq->flush_rq, hctx_idx);
 exit_hctx:
    if (set->ops->exit_hctx)
        set->ops->exit_hctx(hctx, hctx_idx);
 unregister_cpu_notifier:
    //blk_mq_remove_cpuhp(hctx);
    return -1;
}

static struct blk_mq_hw_ctx *
blk_mq_alloc_and_init_hctx(struct blk_mq_tag_set *set,
                           struct request_queue *q,
                           int hctx_idx, int node)
{
    struct blk_mq_hw_ctx *hctx = NULL, *tmp;

    /* reuse dead hctx first */
    spin_lock(&q->unused_hctx_lock);
    list_for_each_entry(tmp, &q->unused_hctx_list, hctx_list) {
        if (tmp->numa_node == node) {
            hctx = tmp;
            break;
        }
    }

    if (hctx)
        list_del_init(&hctx->hctx_list);
    spin_unlock(&q->unused_hctx_lock);

    if (!hctx)
        hctx = blk_mq_alloc_hctx(q, set, node);
    if (!hctx)
        goto fail;

    if (blk_mq_init_hctx(q, set, hctx, hctx_idx))
        goto free_hctx;

    return hctx;

 free_hctx:
    kobject_put(&hctx->kobj);
 fail:
    return NULL;
}

static void blk_mq_realloc_hw_ctxs(struct blk_mq_tag_set *set,
                                   struct request_queue *q)
{
    struct blk_mq_hw_ctx *hctx;
    unsigned long i, j;

    /* protect against switching io scheduler  */
    mutex_lock(&q->sysfs_lock);
    for (i = 0; i < set->nr_hw_queues; i++) {
        int old_node;
        int node = blk_mq_get_hctx_node(set, i);
        struct blk_mq_hw_ctx *old_hctx = xa_load(&q->hctx_table, i);

        if (old_hctx) {
            old_node = old_hctx->numa_node;
            blk_mq_exit_hctx(q, set, old_hctx, i);
        }

        if (!blk_mq_alloc_and_init_hctx(set, q, i, node)) {
            if (!old_hctx)
                break;
            pr_warn("Allocate new hctx on node %d fails, "
                    "fallback to previous one on node %d\n",
                    node, old_node);
            hctx = blk_mq_alloc_and_init_hctx(set, q, i, old_node);
            WARN_ON_ONCE(!hctx);
        }
    }
    /*
     * Increasing nr_hw_queues fails. Free the newly allocated
     * hctxs and keep the previous q->nr_hw_queues.
     */
    if (i != set->nr_hw_queues) {
        j = q->nr_hw_queues;
    } else {
        j = i;
        q->nr_hw_queues = set->nr_hw_queues;
    }

    xa_for_each_start(&q->hctx_table, j, hctx, j)
        blk_mq_exit_hctx(q, set, hctx, j);
    mutex_unlock(&q->sysfs_lock);
}

static void blk_mq_init_cpu_queues(struct request_queue *q,
                                   unsigned int nr_hw_queues)
{
    struct blk_mq_tag_set *set = q->tag_set;
    unsigned int i, j;

    for_each_possible_cpu(i) {
        struct blk_mq_ctx *__ctx = per_cpu_ptr(q->queue_ctx, i);
        struct blk_mq_hw_ctx *hctx;
        int k;

        __ctx->cpu = i;
        spin_lock_init(&__ctx->lock);
        for (k = HCTX_TYPE_DEFAULT; k < HCTX_MAX_TYPES; k++)
            INIT_LIST_HEAD(&__ctx->rq_lists[k]);

        __ctx->queue = q;

        /*
         * Set local node, IFF we have more than one hw queue. If
         * not, we remain on the home node of the device
         */
        for (j = 0; j < set->nr_maps; j++) {
            hctx = blk_mq_map_queue_type(q, j, i);
            if (nr_hw_queues > 1 && hctx->numa_node == NUMA_NO_NODE)
                hctx->numa_node = cpu_to_node(i);
        }
    }
}

static void
blk_mq_add_queue_tag_set(struct blk_mq_tag_set *set, struct request_queue *q)
{
    mutex_lock(&set->tag_list_lock);

    /*
     * Check to see if we're transitioning to shared (from 1 to 2 queues).
     */
    if (!list_empty(&set->tag_list) &&
        !(set->flags & BLK_MQ_F_TAG_QUEUE_SHARED)) {
        set->flags |= BLK_MQ_F_TAG_QUEUE_SHARED;
        /* update existing queue */
        //blk_mq_update_tag_set_shared(set, true);
        panic("%s: END!\n", __func__);
    }
    if (set->flags & BLK_MQ_F_TAG_QUEUE_SHARED) {
        //queue_set_hctx_shared(q, true);
        panic("%s: END!\n", __func__);
    }
    list_add_tail(&q->tag_set_list, &set->tag_list);

    mutex_unlock(&set->tag_list_lock);
}

static void __blk_mq_free_map_and_rqs(struct blk_mq_tag_set *set,
                      unsigned int hctx_idx)
{
    if (!blk_mq_is_shared_tags(set->flags))
        blk_mq_free_map_and_rqs(set, set->tags[hctx_idx], hctx_idx);

    set->tags[hctx_idx] = NULL;
}

static inline int blk_mq_first_mapped_cpu(struct blk_mq_hw_ctx *hctx)
{
    int cpu = cpumask_first_and(hctx->cpumask, cpu_online_mask);

    if (cpu >= nr_cpu_ids)
        cpu = cpumask_first(hctx->cpumask);
    return cpu;
}

static void blk_mq_map_swqueue(struct request_queue *q)
{
    unsigned int j, hctx_idx;
    unsigned long i;
    struct blk_mq_hw_ctx *hctx;
    struct blk_mq_ctx *ctx;
    struct blk_mq_tag_set *set = q->tag_set;

    queue_for_each_hw_ctx(q, hctx, i) {
        cpumask_clear(hctx->cpumask);
        hctx->nr_ctx = 0;
        hctx->dispatch_from = NULL;
    }

    /*
     * Map software to hardware queues.
     *
     * If the cpu isn't present, the cpu is mapped to first hctx.
     */
    for_each_possible_cpu(i) {
        ctx = per_cpu_ptr(q->queue_ctx, i);
        for (j = 0; j < set->nr_maps; j++) {
            if (!set->map[j].nr_queues) {
                ctx->hctxs[j] = blk_mq_map_queue_type(q, HCTX_TYPE_DEFAULT, i);
                continue;
            }
            hctx_idx = set->map[j].mq_map[i];
            /* unmapped hw queue can be remapped after CPU topo changed */
            if (!set->tags[hctx_idx] &&
                !__blk_mq_alloc_map_and_rqs(set, hctx_idx)) {
                /*
                 * If tags initialization fail for some hctx,
                 * that hctx won't be brought online.  In this
                 * case, remap the current ctx to hctx[0] which
                 * is guaranteed to always have tags allocated
                 */
                set->map[j].mq_map[i] = 0;
            }

            hctx = blk_mq_map_queue_type(q, j, i);
            ctx->hctxs[j] = hctx;
            /*
             * If the CPU is already set in the mask, then we've
             * mapped this one already. This can happen if
             * devices share queues across queue maps.
             */
            if (cpumask_test_cpu(i, hctx->cpumask))
                continue;

            cpumask_set_cpu(i, hctx->cpumask);
            hctx->type = j;
            ctx->index_hw[hctx->type] = hctx->nr_ctx;
            hctx->ctxs[hctx->nr_ctx++] = ctx;

            /*
             * If the nr_ctx type overflows, we have exceeded the
             * amount of sw queues we can support.
             */
            BUG_ON(!hctx->nr_ctx);
        }

        for (; j < HCTX_MAX_TYPES; j++)
            ctx->hctxs[j] = blk_mq_map_queue_type(q, HCTX_TYPE_DEFAULT, i);
    }

    queue_for_each_hw_ctx(q, hctx, i) {
        /*
         * If no software queues are mapped to this hardware queue,
         * disable it and free the request entries.
         */
        if (!hctx->nr_ctx) {
            /* Never unmap queue 0.  We need it as a
             * fallback in case of a new remap fails
             * allocation
             */
            if (i)
                __blk_mq_free_map_and_rqs(set, i);

            hctx->tags = NULL;
            continue;
        }

        hctx->tags = set->tags[i];
        WARN_ON(!hctx->tags);

        /*
         * Set the map size to the number of mapped software queues.
         * This is more accurate and more efficient than looping
         * over all possibly mapped software queues.
         */
        sbitmap_resize(&hctx->ctx_map, hctx->nr_ctx);

        /*
         * Initialize batch roundrobin counts
         */
        hctx->next_cpu = blk_mq_first_mapped_cpu(hctx);
        hctx->next_cpu_batch = BLK_MQ_CPU_WORK_BATCH;
    }
}

int blk_mq_init_allocated_queue(struct blk_mq_tag_set *set,
                                struct request_queue *q)
{
    WARN_ON_ONCE(blk_queue_has_srcu(q) != !!(set->flags & BLK_MQ_F_BLOCKING));

    /* mark the queue as mq asap */
    q->mq_ops = set->ops;

#if 0
    q->poll_cb = blk_stat_alloc_callback(blk_mq_poll_stats_fn,
                                         blk_mq_poll_stats_bkt,
                                         BLK_MQ_POLL_STATS_BKTS, q);
    if (!q->poll_cb)
        goto err_exit;
#endif

    if (blk_mq_alloc_ctxs(q))
        goto err_poll;

    /* init q->mq_kobj and sw queues' kobjects */
    blk_mq_sysfs_init(q);

    INIT_LIST_HEAD(&q->unused_hctx_list);
    spin_lock_init(&q->unused_hctx_lock);

    xa_init(&q->hctx_table);

    blk_mq_realloc_hw_ctxs(set, q);
    if (!q->nr_hw_queues)
        goto err_hctxs;

#if 0
    INIT_WORK(&q->timeout_work, blk_mq_timeout_work);
    blk_queue_rq_timeout(q, set->timeout ? set->timeout : 30 * HZ);
#endif

    q->tag_set = set;

    q->queue_flags |= QUEUE_FLAG_MQ_DEFAULT;
    blk_mq_update_poll_flag(q);

#if 0
    INIT_DELAYED_WORK(&q->requeue_work, blk_mq_requeue_work);
#endif
    INIT_LIST_HEAD(&q->requeue_list);
    spin_lock_init(&q->requeue_lock);

    q->nr_requests = set->queue_depth;

    /*
     * Default to classic polling
     */
    q->poll_nsec = BLK_MQ_POLL_CLASSIC;

    blk_mq_init_cpu_queues(q, set->nr_hw_queues);
    blk_mq_add_queue_tag_set(set, q);
    blk_mq_map_swqueue(q);

    return 0;

err_hctxs:
    xa_destroy(&q->hctx_table);
    q->nr_hw_queues = 0;
    //blk_mq_sysfs_deinit(q);
err_poll:
#if 0
    blk_stat_free_callback(q->poll_cb);
    q->poll_cb = NULL;
#endif
err_exit:
    q->mq_ops = NULL;
    return -ENOMEM;
}

static struct request_queue *
blk_mq_init_queue_data(struct blk_mq_tag_set *set, void *queuedata)
{
    struct request_queue *q;
    int ret;

    q = blk_alloc_queue(set->numa_node, set->flags & BLK_MQ_F_BLOCKING);
    if (!q)
        return ERR_PTR(-ENOMEM);
    q->queuedata = queuedata;
    ret = blk_mq_init_allocated_queue(set, q);
    if (ret) {
        blk_cleanup_queue(q);
        return ERR_PTR(ret);
    }
    return q;
}

struct gendisk *
__blk_mq_alloc_disk(struct blk_mq_tag_set *set, void *queuedata,
                    struct lock_class_key *lkclass)
{
    struct request_queue *q;
    struct gendisk *disk;

    q = blk_mq_init_queue_data(set, queuedata);
    if (IS_ERR(q))
        return ERR_CAST(q);

    disk = __alloc_disk_node(q, set->numa_node, lkclass);
    if (!disk) {
        blk_cleanup_queue(q);
        return ERR_PTR(-ENOMEM);
    }
    return disk;
}
EXPORT_SYMBOL(__blk_mq_alloc_disk);

static bool
blk_mq_attempt_bio_merge(struct request_queue *q,
                         struct bio *bio, unsigned int nr_segs)
{
    if (!blk_queue_nomerges(q) && bio_mergeable(bio)) {
        if (blk_attempt_plug_merge(q, bio, nr_segs))
            return true;
        if (blk_mq_sched_bio_merge(q, bio, nr_segs))
            return true;
    }
    return false;
}

static inline struct request *
blk_mq_get_cached_request(struct request_queue *q,
                          struct blk_plug *plug, struct bio **bio,
                          unsigned int nsegs)
{
    struct request *rq;

    if (!plug)
        return NULL;
    rq = rq_list_peek(&plug->cached_rq);
    if (!rq || rq->q != q)
        return NULL;

    if (blk_mq_attempt_bio_merge(q, *bio, nsegs)) {
        *bio = NULL;
        return NULL;
    }

    panic("%s: END!\n", __func__);
}

static inline struct request *
__blk_mq_alloc_requests_batch(struct blk_mq_alloc_data *data, u64 alloc_time_ns)
{
    unsigned int tag, tag_offset;
    struct blk_mq_tags *tags;
    struct request *rq;
    unsigned long tag_mask;
    int i, nr = 0;

    tag_mask = blk_mq_get_tags(data, data->nr_tags, &tag_offset);
    if (unlikely(!tag_mask))
        return NULL;

    panic("%s: END!\n", __func__);
}

static struct request *
blk_mq_rq_ctx_init(struct blk_mq_alloc_data *data,
                   struct blk_mq_tags *tags,
                   unsigned int tag,
                   u64 alloc_time_ns)
{
    struct blk_mq_ctx *ctx = data->ctx;
    struct blk_mq_hw_ctx *hctx = data->hctx;
    struct request_queue *q = data->q;
    struct request *rq = tags->static_rqs[tag];

    rq->q = q;
    rq->mq_ctx = ctx;
    rq->mq_hctx = hctx;
    rq->cmd_flags = data->cmd_flags;

    if (data->flags & BLK_MQ_REQ_PM)
        data->rq_flags |= RQF_PM;
    if (blk_queue_io_stat(q))
        data->rq_flags |= RQF_IO_STAT;
    rq->rq_flags = data->rq_flags;

    if (!(data->rq_flags & RQF_ELV)) {
        rq->tag = tag;
        rq->internal_tag = BLK_MQ_NO_TAG;
    } else {
        rq->tag = BLK_MQ_NO_TAG;
        rq->internal_tag = tag;
    }
    rq->timeout = 0;

    if (blk_mq_need_time_stamp(rq)) {
        //rq->start_time_ns = ktime_get_ns();
        rq->start_time_ns = 0;
        pr_warn("%s: blk_mq_need_time_stamp!\n", __func__);
    } else {
        rq->start_time_ns = 0;
    }
    rq->part = NULL;
    rq->io_start_time_ns = 0;
    rq->stats_sectors = 0;
    rq->nr_phys_segments = 0;
    rq->end_io = NULL;
    rq->end_io_data = NULL;

    INIT_LIST_HEAD(&rq->queuelist);
    /* tag was already set */
    WRITE_ONCE(rq->deadline, 0);
    req_ref_set(rq, 1);

    if (rq->rq_flags & RQF_ELV) {
        struct elevator_queue *e = data->q->elevator;

        INIT_HLIST_NODE(&rq->hash);
        RB_CLEAR_NODE(&rq->rb_node);

        if (!op_is_flush(data->cmd_flags) &&
            e->type->ops.prepare_request) {
            e->type->ops.prepare_request(rq);
            rq->rq_flags |= RQF_ELVPRIV;
        }
    }

    return rq;
}

static struct request *__blk_mq_alloc_requests(struct blk_mq_alloc_data *data)
{
    struct request_queue *q = data->q;
    u64 alloc_time_ns = 0;
    struct request *rq;
    unsigned int tag;

    if (data->cmd_flags & REQ_NOWAIT)
        data->flags |= BLK_MQ_REQ_NOWAIT;

    if (q->elevator) {
        struct elevator_queue *e = q->elevator;

        data->rq_flags |= RQF_ELV;

        /*
         * Flush/passthrough requests are special and go directly to the
         * dispatch list. Don't include reserved tags in the
         * limiting, as it isn't useful.
         */
        if (!op_is_flush(data->cmd_flags) &&
            !blk_op_is_passthrough(data->cmd_flags) &&
            e->type->ops.limit_depth &&
            !(data->flags & BLK_MQ_REQ_RESERVED))
            e->type->ops.limit_depth(data->cmd_flags, data);
    }

 retry:
    data->ctx = blk_mq_get_ctx(q);
    data->hctx = blk_mq_map_queue(q, data->cmd_flags, data->ctx);
    if (!(data->rq_flags & RQF_ELV))
        blk_mq_tag_busy(data->hctx);

    /*
     * Try batched alloc if we want more than 1 tag.
     */
    if (data->nr_tags > 1) {
        rq = __blk_mq_alloc_requests_batch(data, alloc_time_ns);
        if (rq)
            return rq;
        data->nr_tags = 1;
    }

    /*
     * Waiting allocations only fail because of an inactive hctx.  In that
     * case just retry the hctx assignment and tag allocation as CPU hotplug
     * should have migrated us to an online CPU by now.
     */
    tag = blk_mq_get_tag(data);
    if (tag == BLK_MQ_NO_TAG) {
        if (data->flags & BLK_MQ_REQ_NOWAIT)
            return NULL;
#if 0
        /*
         * Give up the CPU and sleep for a random short time to
         * ensure that thread using a realtime scheduling class
         * are migrated off the CPU, and thus off the hctx that
         * is going away.
         */
        msleep(3);
#endif
        goto retry;
    }

    return blk_mq_rq_ctx_init(data, blk_mq_tags_from_data(data), tag,
                              alloc_time_ns);
}

static struct request *
blk_mq_get_new_requests(struct request_queue *q,
                        struct blk_plug *plug,
                        struct bio *bio,
                        unsigned int nsegs)
{
    struct blk_mq_alloc_data data = {
        .q          = q,
        .nr_tags    = 1,
        .cmd_flags  = bio->bi_opf,
    };
    struct request *rq;

    if (unlikely(bio_queue_enter(bio)))
        return NULL;

    if (blk_mq_attempt_bio_merge(q, bio, nsegs))
        goto queue_exit;

#if 0
    rq_qos_throttle(q, bio);
#endif

    if (plug) {
        data.nr_tags = plug->nr_ios;
        plug->nr_ios = 1;
        data.cached_rq = &plug->cached_rq;
    }

    rq = __blk_mq_alloc_requests(&data);
    if (rq)
        return rq;

    panic("%s: END!\n", __func__);

 queue_exit:
    blk_queue_exit(q);
    return NULL;
}

static void blk_mq_bio_to_request(struct request *rq, struct bio *bio,
                                  unsigned int nr_segs)
{
    int err;

    if (bio->bi_opf & REQ_RAHEAD)
        rq->cmd_flags |= REQ_FAILFAST_MASK;

    rq->__sector = bio->bi_iter.bi_sector;
    blk_rq_bio_prep(rq, bio, nr_segs);

    //blk_account_io_start(rq);
}

static void blk_add_rq_to_plug(struct blk_plug *plug, struct request *rq)
{
    panic("%s: END!\n", __func__);
}

static bool __blk_mq_alloc_driver_tag(struct request *rq)
{
    panic("%s: END!\n", __func__);
}

bool __blk_mq_get_driver_tag(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
    if (rq->tag == BLK_MQ_NO_TAG && !__blk_mq_alloc_driver_tag(rq))
        return false;

    if ((hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED) &&
        !(rq->rq_flags & RQF_MQ_INFLIGHT)) {
        rq->rq_flags |= RQF_MQ_INFLIGHT;
        __blk_mq_inc_active_requests(hctx);
    }
    hctx->tags->rqs[rq->tag] = rq;
    return true;
}

#define BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT  8
#define BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR  4

/*
 * Update dispatch busy with the Exponential Weighted Moving Average(EWMA):
 * - EWMA is one simple way to compute running average value
 * - weight(7/8 and 1/8) is applied so that it can decrease exponentially
 * - take 4 as factor for avoiding to get too small(0) result, and this
 *   factor doesn't matter because EWMA decreases exponentially
 */
static void blk_mq_update_dispatch_busy(struct blk_mq_hw_ctx *hctx, bool busy)
{
    unsigned int ewma;

    ewma = hctx->dispatch_busy;

    if (!ewma && !busy)
        return;

    ewma *= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT - 1;
    if (busy)
        ewma += 1 << BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR;
    ewma /= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT;

    hctx->dispatch_busy = ewma;
}

static void __blk_mq_requeue_request(struct request *rq)
{
    struct request_queue *q = rq->q;

    blk_mq_put_driver_tag(rq);

    //rq_qos_requeue(q, rq);

    if (blk_mq_request_started(rq)) {
        WRITE_ONCE(rq->state, MQ_RQ_IDLE);
        rq->rq_flags &= ~RQF_TIMED_OUT;
    }
}

static blk_status_t
__blk_mq_issue_directly(struct blk_mq_hw_ctx *hctx,
                        struct request *rq, bool last)
{
    struct request_queue *q = rq->q;
    struct blk_mq_queue_data bd = {
        .rq = rq,
        .last = last,
    };
    blk_status_t ret;

    /*
     * For OK queue, we are done. For error, caller may kill it.
     * Any other error (busy), just add it to our list as we
     * previously would have done.
     */
    ret = q->mq_ops->queue_rq(hctx, &bd);
    switch (ret) {
    case BLK_STS_OK:
        blk_mq_update_dispatch_busy(hctx, false);
        break;
    case BLK_STS_RESOURCE:
    case BLK_STS_DEV_RESOURCE:
        blk_mq_update_dispatch_busy(hctx, true);
        __blk_mq_requeue_request(rq);
        break;
    default:
        blk_mq_update_dispatch_busy(hctx, false);
        break;
    }

    panic("%s: END!\n", __func__);
    return ret;
}

static blk_status_t
__blk_mq_try_issue_directly(struct blk_mq_hw_ctx *hctx,
                            struct request *rq,
                            bool bypass_insert, bool last)
{
    struct request_queue *q = rq->q;
    bool run_queue = true;
    int budget_token;

    /*
     * RCU or SRCU read lock is needed before checking quiesced flag.
     *
     * When queue is stopped or quiesced, ignore 'bypass_insert' from
     * blk_mq_request_issue_directly(), and return BLK_STS_OK to caller,
     * and avoid driver to try to dispatch again.
     */
    if (blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)) {
        run_queue = false;
        bypass_insert = false;
        goto insert;
    }

    if ((rq->rq_flags & RQF_ELV) && !bypass_insert)
        goto insert;

    budget_token = blk_mq_get_dispatch_budget(q);
    if (budget_token < 0)
        goto insert;

    blk_mq_set_rq_budget_token(rq, budget_token);

    if (!blk_mq_get_driver_tag(rq)) {
        blk_mq_put_dispatch_budget(q, budget_token);
        goto insert;
    }

    return __blk_mq_issue_directly(hctx, rq, last);

 insert:
    if (bypass_insert)
        return BLK_STS_RESOURCE;

    blk_mq_sched_insert_request(rq, false, run_queue, false);

    return BLK_STS_OK;
}

/**
 * blk_mq_try_issue_directly - Try to send a request directly to device driver.
 * @hctx: Pointer of the associated hardware queue.
 * @rq: Pointer to request to be sent.
 *
 * If the device has enough resources to accept a new request now, send the
 * request directly to device driver. Else, insert at hctx->dispatch queue, so
 * we can try send it another time in the future. Requests inserted at this
 * queue have higher priority.
 */
static void blk_mq_try_issue_directly(struct blk_mq_hw_ctx *hctx,
                                      struct request *rq)
{
    blk_status_t ret = __blk_mq_try_issue_directly(hctx, rq, false, true);

    panic("%s: END!\n", __func__);
}

/**
 * blk_mq_submit_bio - Create and send a request to block device.
 * @bio: Bio pointer.
 *
 * Builds up a request structure from @q and @bio and send to the device. The
 * request may not be queued directly to hardware if:
 * * This request can be merged with another one
 * * We want to place request at plug queue for possible future merging
 * * There is an IO scheduler active at this queue
 *
 * It will not queue the request if there is an error with the bio, or at the
 * request creation.
 */
void blk_mq_submit_bio(struct bio *bio)
{
    struct request_queue *q = bdev_get_queue(bio->bi_bdev);
    struct blk_plug *plug = blk_mq_plug(q, bio);
    const int is_sync = op_is_sync(bio->bi_opf);
    struct request *rq;
    unsigned int nr_segs = 1;
    blk_status_t ret;

    blk_queue_bounce(q, &bio);
    if (blk_may_split(q, bio))
        __blk_queue_split(q, &bio, &nr_segs);

    rq = blk_mq_get_cached_request(q, plug, &bio, nr_segs);
    if (!rq) {
        if (!bio)
            return;
        rq = blk_mq_get_new_requests(q, plug, bio, nr_segs);
        if (unlikely(!rq))
            return;
    }

    //rq_qos_track(q, rq, bio);

    blk_mq_bio_to_request(rq, bio, nr_segs);

    if (op_is_flush(bio->bi_opf)) {
        //blk_insert_flush(rq);
        panic("%s: op_is_flush!\n", __func__);
        return;
    }

    if (plug)
        blk_add_rq_to_plug(plug, rq);
    else if ((rq->rq_flags & RQF_ELV) ||
             (rq->mq_hctx->dispatch_busy && (q->nr_hw_queues == 1 || !is_sync)))
        blk_mq_sched_insert_request(rq, false, true, true);
    else
        blk_mq_run_dispatch_ops(rq->q,
                                blk_mq_try_issue_directly(rq->mq_hctx, rq));
}

/**
 * blk_mq_start_request - Start processing a request
 * @rq: Pointer to request to be started
 *
 * Function used by device drivers to notify the block layer that a request
 * is going to be processed now, so blk layer can do proper initializations
 * such as starting the timeout timer.
 */
void blk_mq_start_request(struct request *rq)
{
    struct request_queue *q = rq->q;

    if (test_bit(QUEUE_FLAG_STATS, &q->queue_flags)) {
#if 0
        rq->io_start_time_ns = ktime_get_ns();
        rq->stats_sectors = blk_rq_sectors(rq);
        rq->rq_flags |= RQF_STATS;
        rq_qos_issue(q, rq);
        panic("%s: QUEUE_FLAG_STATS!\n", __func__);
#endif
    }

    WARN_ON_ONCE(blk_mq_rq_state(rq) != MQ_RQ_IDLE);

    //Todo
    //blk_add_timer(rq);
    WRITE_ONCE(rq->state, MQ_RQ_IN_FLIGHT);

#if 0
    if (rq->bio && rq->bio->bi_opf & REQ_POLLED)
        WRITE_ONCE(rq->bio->bi_cookie, blk_rq_to_qc(rq));
#endif
}
EXPORT_SYMBOL(blk_mq_start_request);
