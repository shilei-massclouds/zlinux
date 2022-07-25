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

#endif /* BLK_INTERNAL_H */
