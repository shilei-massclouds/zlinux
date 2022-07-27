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
    printk("%s: step1\n", __func__);
    hctx = blk_mq_map_queue(q, bio->bi_opf, ctx);
    printk("%s: step2\n", __func__);
    type = hctx->type;
    printk("%s: step3\n", __func__);
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
