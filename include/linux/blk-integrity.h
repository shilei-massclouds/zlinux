/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BLK_INTEGRITY_H
#define _LINUX_BLK_INTEGRITY_H

#include <linux/blk-mq.h>

struct request;

static inline int blk_rq_count_integrity_sg(struct request_queue *q,
                        struct bio *b)
{
    return 0;
}
static inline int blk_rq_map_integrity_sg(struct request_queue *q,
                      struct bio *b,
                      struct scatterlist *s)
{
    return 0;
}
static inline struct blk_integrity *bdev_get_integrity(struct block_device *b)
{
    return NULL;
}
static inline struct blk_integrity *blk_get_integrity(struct gendisk *disk)
{
    return NULL;
}
static inline bool
blk_integrity_queue_supports_integrity(struct request_queue *q)
{
    return false;
}
static inline int blk_integrity_compare(struct gendisk *a, struct gendisk *b)
{
    return 0;
}
static inline void blk_integrity_register(struct gendisk *d,
                     struct blk_integrity *b)
{
}
static inline void blk_integrity_unregister(struct gendisk *d)
{
}
static inline void blk_queue_max_integrity_segments(struct request_queue *q,
                            unsigned int segs)
{
}
static inline unsigned short
queue_max_integrity_segments(const struct request_queue *q)
{
    return 0;
}

static inline unsigned int bio_integrity_intervals(struct blk_integrity *bi,
                           unsigned int sectors)
{
    return 0;
}

static inline unsigned int bio_integrity_bytes(struct blk_integrity *bi,
                           unsigned int sectors)
{
    return 0;
}
static inline int blk_integrity_rq(struct request *rq)
{
    return 0;
}

static inline struct bio_vec *rq_integrity_vec(struct request *rq)
{
    return NULL;
}

#endif /* _LINUX_BLK_INTEGRITY_H */
