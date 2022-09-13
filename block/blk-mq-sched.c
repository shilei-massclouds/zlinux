// SPDX-License-Identifier: GPL-2.0
/*
 * blk-mq scheduling framework
 *
 * Copyright (C) 2016 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/blk-mq.h>
//#include <linux/list_sort.h>

#include "blk.h"
#include "blk-mq.h"
//#include "blk-mq-debugfs.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"
//#include "blk-wbt.h"

bool blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio,
                            unsigned int nr_segs)
{
    struct elevator_queue *e = q->elevator;
    struct blk_mq_ctx *ctx;
    struct blk_mq_hw_ctx *hctx;
    bool ret = false;
    enum hctx_type type;

    if (e && e->type->ops.bio_merge) {
        ret = e->type->ops.bio_merge(q, bio, nr_segs);
        goto out_put;
    }

    ctx = blk_mq_get_ctx(q);
    hctx = blk_mq_map_queue(q, bio->bi_opf, ctx);
    type = hctx->type;
    if (!(hctx->flags & BLK_MQ_F_SHOULD_MERGE) ||
        list_empty_careful(&ctx->rq_lists[type]))
        goto out_put;

    panic("%s: END!\n", __func__);
    spin_unlock(&ctx->lock);

 out_put:
    return ret;
}

void blk_mq_sched_insert_request(struct request *rq, bool at_head,
                                 bool run_queue, bool async)
{
    panic("%s: END!\n", __func__);
}

void __blk_mq_sched_restart(struct blk_mq_hw_ctx *hctx)
{
    clear_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);

    /*
     * Order clearing SCHED_RESTART and list_empty_careful(&hctx->dispatch)
     * in blk_mq_run_hw_queue(). Its pair is the barrier in
     * blk_mq_dispatch_rq_list(). So dispatch code won't see SCHED_RESTART,
     * meantime new request added to hctx->dispatch is missed to check in
     * blk_mq_run_hw_queue().
     */
    smp_mb();

    //blk_mq_run_hw_queue(hctx, true);
    panic("%s: END!\n", __func__);
}

void blk_mq_sched_insert_requests(struct blk_mq_hw_ctx *hctx,
                                  struct blk_mq_ctx *ctx,
                                  struct list_head *list,
                                  bool run_queue_async)
{
    struct elevator_queue *e;
    struct request_queue *q = hctx->queue;

    /*
     * blk_mq_sched_insert_requests() is called from flush plug
     * context only, and hold one usage counter to prevent queue
     * from being released.
     */
    percpu_ref_get(&q->q_usage_counter);

    e = hctx->queue->elevator;
    if (e) {
        e->type->ops.insert_requests(hctx, list, false);
    } else {
        /*
         * try to issue requests directly if the hw queue isn't
         * busy in case of 'none' scheduler, and this way may save
         * us one extra enqueue & dequeue to sw queue.
         */
        if (!hctx->dispatch_busy && !run_queue_async) {
            blk_mq_run_dispatch_ops(hctx->queue,
                blk_mq_try_issue_list_directly(hctx, list));
            if (list_empty(list))
                goto out;
        }
        blk_mq_insert_requests(hctx, ctx, list);
    }

    blk_mq_run_hw_queue(hctx, run_queue_async);
 out:
    percpu_ref_put(&q->q_usage_counter);
}
