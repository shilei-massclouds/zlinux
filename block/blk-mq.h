/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INT_BLK_MQ_H
#define INT_BLK_MQ_H

#if 0
#include "blk-stat.h"
#endif
#include "blk-mq-tag.h"

struct blk_mq_tag_set;

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

#endif /* INT_BLK_MQ_H */
