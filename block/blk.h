/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BLK_INTERNAL_H
#define BLK_INTERNAL_H

#include <linux/memblock.h> /* for max_pfn/max_low_pfn */
#if 0
#include <linux/blk-crypto.h>
#include "blk-crypto-internal.h"
#endif

struct elevator_type;

extern struct kmem_cache *blk_requestq_cachep;
extern struct kmem_cache *blk_requestq_srcu_cachep;

static inline struct kmem_cache *blk_get_queue_kmem_cache(bool srcu)
{
    if (srcu)
        return blk_requestq_srcu_cachep;
    return blk_requestq_cachep;
}
struct request_queue *blk_alloc_queue(int node_id, bool alloc_srcu);

struct request_queue *blk_alloc_queue(int node_id, bool alloc_srcu);

int blk_dev_init(void);

static inline void __blk_get_queue(struct request_queue *q)
{
    kobject_get(&q->kobj);
}

long blkdev_ioctl(struct file *file, unsigned cmd, unsigned long arg);

extern const struct address_space_operations def_blk_aops;

static inline void bio_clear_polled(struct bio *bio)
{
    /* can't support alloc cache if we turn off polling */
    bio_clear_flag(bio, BIO_PERCPU_CACHE);
    bio->bi_opf &= ~REQ_POLLED;
}

static inline bool blk_try_enter_queue(struct request_queue *q, bool pm)
{
    panic("%s: END!\n", __func__);
}

int __bio_queue_enter(struct request_queue *q, struct bio *bio);

static inline int bio_queue_enter(struct bio *bio)
{
    struct request_queue *q = bdev_get_queue(bio->bi_bdev);

    if (blk_try_enter_queue(q, false))
        return 0;
    return __bio_queue_enter(q, bio);
}

void __blk_queue_bounce(struct request_queue *q, struct bio **bio);

static inline bool blk_queue_may_bounce(struct request_queue *q)
{
    return false;
}

static inline void blk_queue_bounce(struct request_queue *q, struct bio **bio)
{
    if (unlikely(blk_queue_may_bounce(q) && bio_has_data(*bio))) {
        //__blk_queue_bounce(q, bio);
        panic("%s: END!\n", __func__);
    }
}

static inline bool blk_may_split(struct request_queue *q, struct bio *bio)
{
    switch (bio_op(bio)) {
    case REQ_OP_DISCARD:
    case REQ_OP_SECURE_ERASE:
    case REQ_OP_WRITE_ZEROES:
        return true; /* non-trivial splitting decisions */
    default:
        break;
    }

    /*
     * All drivers must accept single-segments bios that are <= PAGE_SIZE.
     * This is a quick and dirty check that relies on the fact that
     * bi_io_vec[0] is always valid if a bio has data.  The check might
     * lead to occasional false negatives when bios are cloned, but compared
     * to the performance impact of cloned bios themselves the loop below
     * doesn't matter anyway.
     */
    return q->limits.chunk_sectors || bio->bi_vcnt != 1 ||
        bio->bi_io_vec->bv_len + bio->bi_io_vec->bv_offset > PAGE_SIZE;
}

void __blk_queue_split(struct request_queue *q, struct bio **bio,
                       unsigned int *nr_segs);

#endif /* BLK_INTERNAL_H */
