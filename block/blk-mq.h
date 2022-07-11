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

#endif /* INT_BLK_MQ_H */
