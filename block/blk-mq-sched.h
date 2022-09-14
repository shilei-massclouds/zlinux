/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BLK_MQ_SCHED_H
#define BLK_MQ_SCHED_H

#include "elevator.h"
#include "blk-mq.h"
#include "blk-mq-tag.h"

bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
                            unsigned int nr_segs,
                            struct request **merged_request);

bool blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio,
                            unsigned int nr_segs);

static inline bool bio_mergeable(struct bio *bio)
{
    return !(bio->bi_opf & REQ_NOMERGE_FLAGS);
}

void blk_mq_sched_insert_request(struct request *rq, bool at_head,
                                 bool run_queue, bool async);

void blk_mq_sched_insert_requests(struct blk_mq_hw_ctx *hctx,
                                  struct blk_mq_ctx *ctx,
                                  struct list_head *list, bool run_queue_async);

void __blk_mq_sched_restart(struct blk_mq_hw_ctx *hctx);

static inline void blk_mq_sched_restart(struct blk_mq_hw_ctx *hctx)
{
    if (test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
        __blk_mq_sched_restart(hctx);
}

static inline bool blk_mq_sched_has_work(struct blk_mq_hw_ctx *hctx)
{
    struct elevator_queue *e = hctx->queue->elevator;

    if (e && e->type->ops.has_work)
        return e->type->ops.has_work(hctx);

    return false;
}

void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx);

#endif /* BLK_MQ_SCHED_H */
