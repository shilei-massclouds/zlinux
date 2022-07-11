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

#endif /* INT_BLK_MQ_TAG_H */
