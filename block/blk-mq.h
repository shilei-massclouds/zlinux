/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INT_BLK_MQ_H
#define INT_BLK_MQ_H

#include <linux/blk-mq.h>

#if 0
#include "blk-stat.h"
#endif
#include "blk-mq-tag.h"

struct blk_mq_tag_set;

struct blk_mq_tag_set;

struct blk_mq_ctxs {
    struct kobject kobj;
    struct blk_mq_ctx __percpu  *queue_ctx;
};

/**
 * struct blk_mq_ctx - State for a software queue facing the submitting CPUs
 */
struct blk_mq_ctx {
    struct {
        spinlock_t      lock;
        struct list_head    rq_lists[HCTX_MAX_TYPES];
    } ____cacheline_aligned_in_smp;

    unsigned int        cpu;
    unsigned short      index_hw[HCTX_MAX_TYPES];
    struct blk_mq_hw_ctx    *hctxs[HCTX_MAX_TYPES];

    struct request_queue    *queue;
    struct blk_mq_ctxs      *ctxs;
    struct kobject      kobj;
} ____cacheline_aligned_in_smp;

struct blk_mq_alloc_data {
    /* input parameter */
    struct request_queue *q;
    blk_mq_req_flags_t flags;
    unsigned int shallow_depth;
    unsigned int cmd_flags;
    req_flags_t rq_flags;

    /* allocate multiple requests/tags in one go */
    unsigned int nr_tags;
    struct request **cached_rq;

    /* input & output parameter */
    struct blk_mq_ctx *ctx;
    struct blk_mq_hw_ctx *hctx;
};

static inline void blk_mq_clear_mq_map(struct blk_mq_queue_map *qmap)
{
    int cpu;

    for_each_possible_cpu(cpu)
        qmap->mq_map[cpu] = 0;
}

static inline bool blk_mq_is_shared_tags(unsigned int flags)
{
    return flags & BLK_MQ_F_TAG_HCTX_SHARED;
}

void blk_mq_free_rq_map(struct blk_mq_tags *tags);

void blk_mq_free_map_and_rqs(struct blk_mq_tag_set *set,
                             struct blk_mq_tags *tags,
                             unsigned int hctx_idx);

extern int blk_mq_hw_queue_to_node(struct blk_mq_queue_map *qmap, unsigned int);

/*
 * blk_mq_plug() - Get caller context plug
 * @q: request queue
 * @bio : the bio being submitted by the caller context
 *
 * Plugging, by design, may delay the insertion of BIOs into the elevator in
 * order to increase BIO merging opportunities. This however can cause BIO
 * insertion order to change from the order in which submit_bio() is being
 * executed in the case of multiple contexts concurrently issuing BIOs to a
 * device, even if these context are synchronized to tightly control BIO issuing
 * order. While this is not a problem with regular block devices, this ordering
 * change can cause write BIO failures with zoned block devices as these
 * require sequential write patterns to zones. Prevent this from happening by
 * ignoring the plug state of a BIO issuing context if the target request queue
 * is for a zoned block device and the BIO to plug is a write operation.
 *
 * Return current->plug if the bio can be plugged and NULL otherwise
 */
static inline struct blk_plug *
blk_mq_plug(struct request_queue *q, struct bio *bio)
{
    /*
     * For regular block devices or read operations, use the context plug
     * which may be NULL if blk_start_plug() was not executed.
     */
    if (!blk_queue_is_zoned(q) || !op_is_write(bio_op(bio)))
        return current->plug;

    /* Zoned block device write operation case: do not plug the BIO */
    return NULL;
}

void blk_mq_submit_bio(struct bio *bio);

static inline struct blk_mq_ctx *
__blk_mq_get_ctx(struct request_queue *q, unsigned int cpu)
{
    return per_cpu_ptr(q->queue_ctx, cpu);
}

/*
 * This assumes per-cpu software queueing queues. They could be per-node
 * as well, for instance. For now this is hardcoded as-is. Note that we don't
 * care about preemption, since we know the ctx's are persistent. This does
 * mean that we can't rely on ctx always matching the currently running CPU.
 */
static inline struct blk_mq_ctx *blk_mq_get_ctx(struct request_queue *q)
{
    return __blk_mq_get_ctx(q, raw_smp_processor_id());
}

static inline enum hctx_type blk_mq_get_hctx_type(unsigned int flags)
{
    enum hctx_type type = HCTX_TYPE_DEFAULT;

    /*
     * The caller ensure that if REQ_POLLED, poll must be enabled.
     */
    if (flags & REQ_POLLED)
        type = HCTX_TYPE_POLL;
    else if ((flags & REQ_OP_MASK) == REQ_OP_READ)
        type = HCTX_TYPE_READ;
    return type;
}

/*
 * blk_mq_map_queue() - map (cmd_flags,type) to hardware queue
 * @q: request queue
 * @flags: request command flags
 * @ctx: software queue cpu ctx
 */
static inline struct blk_mq_hw_ctx *
blk_mq_map_queue(struct request_queue *q,
                 unsigned int flags,
                 struct blk_mq_ctx *ctx)
{
    return ctx->hctxs[blk_mq_get_hctx_type(flags)];
}

extern void blk_mq_sysfs_init(struct request_queue *q);

extern void blk_mq_hctx_kobj_init(struct blk_mq_hw_ctx *hctx);

/*
 * blk_mq_map_queue_type() - map (hctx_type,cpu) to hardware queue
 * @q: request queue
 * @type: the hctx type index
 * @cpu: CPU
 */
static inline struct blk_mq_hw_ctx *
blk_mq_map_queue_type(struct request_queue *q,
                      enum hctx_type type, unsigned int cpu)
{
    return xa_load(&q->hctx_table, q->tag_set->map[type].mq_map[cpu]);
}

static inline struct blk_mq_tags *
blk_mq_tags_from_data(struct blk_mq_alloc_data *data)
{
    if (!(data->rq_flags & RQF_ELV))
        return data->hctx->tags;
    return data->hctx->sched_tags;
}

/*
 * For shared tag users, we track the number of currently active users
 * and attempt to provide a fair share of the tag depth for each of them.
 */
static inline bool hctx_may_queue(struct blk_mq_hw_ctx *hctx,
                                  struct sbitmap_queue *bt)
{
    unsigned int depth, users;

    if (!hctx || !(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED))
        return true;

    /*
     * Don't try dividing an ant
     */
    if (bt->sb.depth == 1)
        return true;

    panic("%s: END!\n", __func__);
}

/* run the code block in @dispatch_ops with rcu/srcu read lock held */
#define __blk_mq_run_dispatch_ops(q, check_sleep, dispatch_ops) \
do {                                \
    if (!blk_queue_has_srcu(q)) {               \
        rcu_read_lock();                \
        (dispatch_ops);                 \
        rcu_read_unlock();              \
    } else {                        \
        int srcu_idx;                   \
                                \
        might_sleep_if(check_sleep);            \
        srcu_idx = srcu_read_lock((q)->srcu);       \
        (dispatch_ops);                 \
        srcu_read_unlock((q)->srcu, srcu_idx);      \
    }                           \
} while (0)

#define blk_mq_run_dispatch_ops(q, dispatch_ops)        \
    __blk_mq_run_dispatch_ops(q, true, dispatch_ops)    \

static inline bool blk_mq_hctx_stopped(struct blk_mq_hw_ctx *hctx)
{
    return test_bit(BLK_MQ_S_STOPPED, &hctx->state);
}

static inline int blk_mq_get_dispatch_budget(struct request_queue *q)
{
    if (q->mq_ops->get_budget)
        return q->mq_ops->get_budget(q);
    return 0;
}

static inline void blk_mq_set_rq_budget_token(struct request *rq, int token)
{
    if (token < 0)
        return;

    if (rq->q->mq_ops->set_rq_budget_token)
        rq->q->mq_ops->set_rq_budget_token(rq, token);
}

bool __blk_mq_get_driver_tag(struct blk_mq_hw_ctx *hctx, struct request *rq);

static inline bool blk_mq_get_driver_tag(struct request *rq)
{
    struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

    if (rq->tag != BLK_MQ_NO_TAG &&
        !(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED)) {
        hctx->tags->rqs[rq->tag] = rq;
        return true;
    }

    return __blk_mq_get_driver_tag(hctx, rq);
}

static inline void __blk_mq_inc_active_requests(struct blk_mq_hw_ctx *hctx)
{
    if (blk_mq_is_shared_tags(hctx->flags))
        atomic_inc(&hctx->queue->nr_active_requests_shared_tags);
    else
        atomic_inc(&hctx->nr_active);
}

static inline void blk_mq_put_dispatch_budget(struct request_queue *q,
                                              int budget_token)
{
    if (q->mq_ops->put_budget)
        q->mq_ops->put_budget(q, budget_token);
}

static inline void
__blk_mq_sub_active_requests(struct blk_mq_hw_ctx *hctx, int val)
{
    if (blk_mq_is_shared_tags(hctx->flags))
        atomic_sub(val, &hctx->queue->nr_active_requests_shared_tags);
    else
        atomic_sub(val, &hctx->nr_active);
}

static inline void __blk_mq_dec_active_requests(struct blk_mq_hw_ctx *hctx)
{
    __blk_mq_sub_active_requests(hctx, 1);
}

static inline int __blk_mq_active_requests(struct blk_mq_hw_ctx *hctx)
{
    if (blk_mq_is_shared_tags(hctx->flags))
        return atomic_read(&hctx->queue->nr_active_requests_shared_tags);
    return atomic_read(&hctx->nr_active);
}

static inline void __blk_mq_put_driver_tag(struct blk_mq_hw_ctx *hctx,
                                           struct request *rq)
{
    blk_mq_put_tag(hctx->tags, rq->mq_ctx, rq->tag);
    rq->tag = BLK_MQ_NO_TAG;

    if (rq->rq_flags & RQF_MQ_INFLIGHT) {
        rq->rq_flags &= ~RQF_MQ_INFLIGHT;
        __blk_mq_dec_active_requests(hctx);
    }
}

static inline void blk_mq_put_driver_tag(struct request *rq)
{
    if (rq->tag == BLK_MQ_NO_TAG || rq->internal_tag == BLK_MQ_NO_TAG)
        return;

    __blk_mq_put_driver_tag(rq->mq_hctx, rq);
}

#endif /* INT_BLK_MQ_H */
