// SPDX-License-Identifier: GPL-2.0
/*
 * Tag allocation using scalable bitmaps. Uses active queue tracking to support
 * fairer distribution of tags between multiple submitters when a shared tag map
 * is used.
 *
 * Copyright (C) 2013-2014 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/blk-mq.h>
#if 0
#include <linux/delay.h>
#include "blk.h"
#include "blk-mq-sched.h"
#endif
#include "blk-mq.h"
#include "blk-mq-tag.h"

static int bt_alloc(struct sbitmap_queue *bt, unsigned int depth,
                    bool round_robin, int node)
{
    return sbitmap_queue_init_node(bt, depth, -1, round_robin, GFP_KERNEL,
                                   node);
}

int blk_mq_init_bitmaps(struct sbitmap_queue *bitmap_tags,
                        struct sbitmap_queue *breserved_tags,
                        unsigned int queue_depth, unsigned int reserved,
                        int node, int alloc_policy)
{
    unsigned int depth = queue_depth - reserved;
    bool round_robin = alloc_policy == BLK_TAG_ALLOC_RR;

    if (bt_alloc(bitmap_tags, depth, round_robin, node))
        return -ENOMEM;
    if (bt_alloc(breserved_tags, reserved, round_robin, node))
        goto free_bitmap_tags;

    return 0;

free_bitmap_tags:
    sbitmap_queue_free(bitmap_tags);
    return -ENOMEM;
}

struct blk_mq_tags *
blk_mq_init_tags(unsigned int total_tags,
                 unsigned int reserved_tags,
                 int node, int alloc_policy)
{
    struct blk_mq_tags *tags;

    if (total_tags > BLK_MQ_TAG_MAX) {
        pr_err("blk-mq: tag depth too large\n");
        return NULL;
    }

    tags = kzalloc_node(sizeof(*tags), GFP_KERNEL, node);
    if (!tags)
        return NULL;

    tags->nr_tags = total_tags;
    tags->nr_reserved_tags = reserved_tags;
    spin_lock_init(&tags->lock);

    if (blk_mq_init_bitmaps(&tags->bitmap_tags, &tags->breserved_tags,
                            total_tags, reserved_tags, node,
                            alloc_policy) < 0) {
        kfree(tags);
        return NULL;
    }
    return tags;
}

void blk_mq_free_tags(struct blk_mq_tags *tags)
{
#if 0
    sbitmap_queue_free(&tags->bitmap_tags);
    sbitmap_queue_free(&tags->breserved_tags);
    kfree(tags);
#endif
    panic("%s: END!\n", __func__);
}

/*
 * If a previously inactive queue goes active, bump the active user count.
 * We need to do this before try to allocate driver tag, then even if fail
 * to get tag when first time, the other shared-tag users could reserve
 * budget for it.
 */
bool __blk_mq_tag_busy(struct blk_mq_hw_ctx *hctx)
{
    panic("%s: END!\n", __func__);
}

/*
 * If a previously busy queue goes inactive, potential waiters could now
 * be allowed to queue. Wake them up and check.
 */
void __blk_mq_tag_idle(struct blk_mq_hw_ctx *hctx)
{
    panic("%s: END!\n", __func__);
}

void blk_mq_put_tag(struct blk_mq_tags *tags, struct blk_mq_ctx *ctx,
                    unsigned int tag)
{
    if (!blk_mq_tag_is_reserved(tags, tag)) {
        const int real_tag = tag - tags->nr_reserved_tags;

        BUG_ON(real_tag >= tags->nr_tags);
        sbitmap_queue_clear(&tags->bitmap_tags, real_tag, ctx->cpu);
    } else {
        BUG_ON(tag >= tags->nr_reserved_tags);
        sbitmap_queue_clear(&tags->breserved_tags, tag, ctx->cpu);
    }
}

static int __blk_mq_get_tag(struct blk_mq_alloc_data *data,
                            struct sbitmap_queue *bt)
{
    if (!data->q->elevator && !(data->flags & BLK_MQ_REQ_RESERVED) &&
        !hctx_may_queue(data->hctx, bt))
        return BLK_MQ_NO_TAG;

    if (data->shallow_depth)
        return sbitmap_queue_get_shallow(bt, data->shallow_depth);
    else
        return __sbitmap_queue_get(bt);
}

unsigned int blk_mq_get_tag(struct blk_mq_alloc_data *data)
{
    struct blk_mq_tags *tags = blk_mq_tags_from_data(data);
    struct sbitmap_queue *bt;
    struct sbq_wait_state *ws;
    //DEFINE_SBQ_WAIT(wait);
    unsigned int tag_offset;
    int tag;

    if (data->flags & BLK_MQ_REQ_RESERVED) {
        if (unlikely(!tags->nr_reserved_tags)) {
            WARN_ON_ONCE(1);
            return BLK_MQ_NO_TAG;
        }
        bt = &tags->breserved_tags;
        tag_offset = 0;
    } else {
        bt = &tags->bitmap_tags;
        tag_offset = tags->nr_reserved_tags;
    }

    tag = __blk_mq_get_tag(data, bt);
    if (tag != BLK_MQ_NO_TAG)
        goto found_tag;

    panic("%s: END!\n", __func__);

 found_tag:
    /*
     * Give up this allocation if the hctx is inactive.  The caller will
     * retry on an active hctx.
     */
    if (unlikely(test_bit(BLK_MQ_S_INACTIVE, &data->hctx->state))) {
        blk_mq_put_tag(tags, data->ctx, tag + tag_offset);
        return BLK_MQ_NO_TAG;
    }
    return tag + tag_offset;
}

unsigned long blk_mq_get_tags(struct blk_mq_alloc_data *data, int nr_tags,
                              unsigned int *offset)
{
    struct blk_mq_tags *tags = blk_mq_tags_from_data(data);
    struct sbitmap_queue *bt = &tags->bitmap_tags;
    unsigned long ret;

    if (data->shallow_depth ||data->flags & BLK_MQ_REQ_RESERVED ||
        data->hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED)
        return 0;
    ret = __sbitmap_queue_get_batch(bt, nr_tags, offset);
    *offset += tags->nr_reserved_tags;
    return ret;
}
