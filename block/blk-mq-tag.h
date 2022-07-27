/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INT_BLK_MQ_TAG_H
#define INT_BLK_MQ_TAG_H

struct blk_mq_alloc_data;

enum {
    BLK_MQ_NO_TAG   = -1U,
    BLK_MQ_TAG_MIN  = 1,
    BLK_MQ_TAG_MAX  = BLK_MQ_NO_TAG - 1,
};

extern struct blk_mq_tags *
blk_mq_init_tags(unsigned int nr_tags,
                 unsigned int reserved_tags,
                 int node, int alloc_policy);

extern void blk_mq_free_tags(struct blk_mq_tags *tags);

extern bool __blk_mq_tag_busy(struct blk_mq_hw_ctx *);
extern void __blk_mq_tag_idle(struct blk_mq_hw_ctx *);

static inline bool blk_mq_tag_busy(struct blk_mq_hw_ctx *hctx)
{
    if (!(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED))
        return false;

    return __blk_mq_tag_busy(hctx);
}

static inline void blk_mq_tag_idle(struct blk_mq_hw_ctx *hctx)
{
    if (!(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED))
        return;

    __blk_mq_tag_idle(hctx);
}

static inline bool blk_mq_tag_is_reserved(struct blk_mq_tags *tags,
                                          unsigned int tag)
{
    return tag < tags->nr_reserved_tags;
}

extern unsigned int blk_mq_get_tag(struct blk_mq_alloc_data *data);

unsigned long blk_mq_get_tags(struct blk_mq_alloc_data *data, int nr_tags,
                              unsigned int *offset);

extern void blk_mq_put_tag(struct blk_mq_tags *tags, struct blk_mq_ctx *ctx,
                           unsigned int tag);

#endif /* INT_BLK_MQ_TAG_H */
