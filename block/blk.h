/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BLK_INTERNAL_H
#define BLK_INTERNAL_H

#include <linux/memblock.h> /* for max_pfn/max_low_pfn */
#include <linux/blk-mq.h>
#include <linux/blk-crypto.h>
#include "blk-crypto-internal.h"

/*
 * Plug flush limits
 */
#define BLK_MAX_REQUEST_COUNT   32
#define BLK_PLUG_FLUSH_SIZE     (128 * 1024)

struct elevator_type;

struct blk_flush_queue {
    unsigned int        flush_pending_idx:1;
    unsigned int        flush_running_idx:1;
    blk_status_t        rq_status;
    unsigned long       flush_pending_since;
    struct list_head    flush_queue[2];
    struct list_head    flush_data_in_flight;
    struct request      *flush_rq;

    spinlock_t          mq_flush_lock;
};

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
    rcu_read_lock();
    if (!percpu_ref_tryget_live_rcu(&q->q_usage_counter))
        goto fail;

    /*
     * The code that increments the pm_only counter must ensure that the
     * counter is globally visible before the queue is unfrozen.
     */
    if (blk_queue_pm_only(q) && (!pm || queue_rpm_status(q) == RPM_SUSPENDED))
        goto fail_put;

    rcu_read_unlock();
    return true;

fail_put:
    blk_queue_exit(q);
fail:
    rcu_read_unlock();
    return false;
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

static inline
bool blk_may_split(struct request_queue *q, struct bio *bio)
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

bool blk_attempt_plug_merge(struct request_queue *q, struct bio *bio,
                            unsigned int nr_segs);
bool blk_bio_list_merge(struct request_queue *q, struct list_head *list,
                        struct bio *bio, unsigned int nr_segs);

struct blk_flush_queue *blk_alloc_flush_queue(int node, int cmd_size,
                                              gfp_t flags);
void blk_free_flush_queue(struct blk_flush_queue *q);

static inline void req_ref_set(struct request *req, int value)
{
    atomic_set(&req->ref, value);
}

static inline int req_ref_read(struct request *req)
{
    return atomic_read(&req->ref);
}

static inline bool
biovec_phys_mergeable(struct request_queue *q,
                      struct bio_vec *vec1, struct bio_vec *vec2)
{
    unsigned long mask = queue_segment_boundary(q);
    phys_addr_t addr1 = page_to_phys(vec1->bv_page) + vec1->bv_offset;
    phys_addr_t addr2 = page_to_phys(vec2->bv_page) + vec2->bv_offset;

    if (addr1 + vec1->bv_len != addr2)
        return false;
    if ((addr1 | mask) != ((addr2 + vec2->bv_len - 1) | mask))
        return false;
    return true;
}

const char *blk_status_to_str(blk_status_t status);

/*
 * Contribute to IO statistics IFF:
 *
 *  a) it's attached to a gendisk, and
 *  b) the queue had IO stats enabled when this request was started
 */
static inline bool blk_do_io_stat(struct request *rq)
{
    return (rq->rq_flags & RQF_IO_STAT) && !blk_rq_is_passthrough(rq);
}

/*
 * Optimized request reference counting. Ideally we'd make timeouts be more
 * clever, as that's the only reason we need references at all... But until
 * this happens, this is faster than using refcount_t. Also see:
 *
 * abc54d634334 ("io_uring: switch to atomic_t for io_kiocb reference count")
 */
#define req_ref_zero_or_close_to_overflow(req)  \
    ((unsigned int) atomic_read(&(req->ref)) + 127u <= 127u)

static inline bool req_ref_put_and_test(struct request *req)
{
    WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
    return atomic_dec_and_test(&req->ref);
}

static inline bool
__bvec_gap_to_prev(struct request_queue *q,
                   struct bio_vec *bprv, unsigned int offset)
{
    return (offset & queue_virt_boundary(q)) ||
        ((bprv->bv_offset + bprv->bv_len) & queue_virt_boundary(q));
}

/*
 * Check if adding a bio_vec after bprv with offset would create a gap in
 * the SG list. Most drivers don't care about this, but some do.
 */
static inline bool bvec_gap_to_prev(struct request_queue *q,
                                    struct bio_vec *bprv, unsigned int offset)
{
    if (!queue_virt_boundary(q))
        return false;
    return __bvec_gap_to_prev(q, bprv, offset);
}

extern struct kobj_type blk_queue_ktype;

static inline bool rq_mergeable(struct request *rq)
{
    if (blk_rq_is_passthrough(rq))
        return false;

    if (req_op(rq) == REQ_OP_FLUSH)
        return false;

    if (req_op(rq) == REQ_OP_WRITE_ZEROES)
        return false;

    if (req_op(rq) == REQ_OP_ZONE_APPEND)
        return false;

    if (rq->cmd_flags & REQ_NOMERGE_FLAGS)
        return false;
    if (rq->rq_flags & RQF_NOMERGE_FLAGS)
        return false;

    return true;
}

static inline bool blk_integrity_merge_rq(struct request_queue *rq,
        struct request *r1, struct request *r2)
{
    return true;
}
static inline bool blk_integrity_merge_bio(struct request_queue *rq,
        struct request *r, struct bio *b)
{
    return true;
}
static inline bool integrity_req_gap_back_merge(struct request *req,
        struct bio *next)
{
    return false;
}
static inline bool integrity_req_gap_front_merge(struct request *req,
        struct bio *bio)
{
    return false;
}
static inline void blk_flush_integrity(void)
{
}
static inline bool bio_integrity_endio(struct bio *bio)
{
    return true;
}
static inline void bio_integrity_free(struct bio *bio)
{
}
static inline int blk_integrity_add(struct gendisk *disk)
{
    return 0;
}
static inline void blk_integrity_del(struct gendisk *disk)
{
}

/*
 * There are two different ways to handle DISCARD merges:
 *  1) If max_discard_segments > 1, the driver treats every bio as a range and
 *     send the bios to controller together. The ranges don't need to be
 *     contiguous.
 *  2) Otherwise, the request will be normal read/write requests.  The ranges
 *     need to be contiguous.
 */
static inline bool blk_discard_mergable(struct request *req)
{
    if (req_op(req) == REQ_OP_DISCARD &&
        queue_max_discard_segments(req->q) > 1)
        return true;
    return false;
}

static inline
void req_set_nomerge(struct request_queue *q, struct request *req)
{
    req->cmd_flags |= REQ_NOMERGE;
    if (req == q->last_merge)
        q->last_merge = NULL;
}

void update_io_ticks(struct block_device *part, unsigned long now,
                     bool end);

#endif /* BLK_INTERNAL_H */
