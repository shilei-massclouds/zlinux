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

static int blk_mq_do_dispatch_sched(struct blk_mq_hw_ctx *hctx)
{
    panic("%s: END!\n", __func__);
}

/*
 * Only SCSI implements .get_budget and .put_budget, and SCSI restarts
 * its queue by itself in its completion handler, so we don't need to
 * restart queue if .get_budget() returns BLK_STS_NO_RESOURCE.
 *
 * Returns -EAGAIN if hctx->dispatch was found non-empty and run_work has to
 * be run again.  This is necessary to avoid starving flushes.
 */
static int blk_mq_do_dispatch_ctx(struct blk_mq_hw_ctx *hctx)
{
    panic("%s: END!\n", __func__);
}

/*
 * Mark a hardware queue as needing a restart. For shared queues, maintain
 * a count of how many hardware queues are marked for restart.
 */
void blk_mq_sched_mark_restart_hctx(struct blk_mq_hw_ctx *hctx)
{
    if (test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
        return;

    set_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_mark_restart_hctx);

static int __blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
    struct request_queue *q = hctx->queue;
    const bool has_sched = q->elevator;
    int ret = 0;
    LIST_HEAD(rq_list);

    /*
     * If we have previous entries on our dispatch list, grab them first for
     * more fair dispatch.
     */
    if (!list_empty_careful(&hctx->dispatch)) {
        spin_lock(&hctx->lock);
        if (!list_empty(&hctx->dispatch))
            list_splice_init(&hctx->dispatch, &rq_list);
        spin_unlock(&hctx->lock);
    }

    /*
     * Only ask the scheduler for requests, if we didn't have residual
     * requests from the dispatch list. This is to avoid the case where
     * we only ever dispatch a fraction of the requests available because
     * of low device queue depth. Once we pull requests out of the IO
     * scheduler, we can no longer merge or sort them. So it's best to
     * leave them there for as long as we can. Mark the hw queue as
     * needing a restart in that case.
     *
     * We want to dispatch from the scheduler if there was nothing
     * on the dispatch list or we were able to dispatch from the
     * dispatch list.
     */
    if (!list_empty(&rq_list)) {
        blk_mq_sched_mark_restart_hctx(hctx);
        if (blk_mq_dispatch_rq_list(hctx, &rq_list, 0)) {
            if (has_sched)
                ret = blk_mq_do_dispatch_sched(hctx);
            else
                ret = blk_mq_do_dispatch_ctx(hctx);
        }
    } else if (has_sched) {
        ret = blk_mq_do_dispatch_sched(hctx);
    } else if (hctx->dispatch_busy) {
        /* dequeue request one by one from sw queue if queue is busy */
        ret = blk_mq_do_dispatch_ctx(hctx);
    } else {
        blk_mq_flush_busy_ctxs(hctx, &rq_list);
        blk_mq_dispatch_rq_list(hctx, &rq_list, 0);
    }

    return ret;
}

void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
    struct request_queue *q = hctx->queue;

    /* RCU or SRCU read lock is needed before checking quiesced flag */
    if (unlikely(blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)))
        return;

    hctx->run++;

    /*
     * A return of -EAGAIN is an indication that hctx->dispatch is not
     * empty and we must run again in order to avoid starving flushes.
     */
    if (__blk_mq_sched_dispatch_requests(hctx) == -EAGAIN) {
        if (__blk_mq_sched_dispatch_requests(hctx) == -EAGAIN)
            blk_mq_run_hw_queue(hctx, true);
    }
}
