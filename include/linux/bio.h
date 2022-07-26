/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2001 Jens Axboe <axboe@suse.de>
 */
#ifndef __LINUX_BIO_H
#define __LINUX_BIO_H

#include <linux/mempool.h>
/* struct bio, bio_vec and BIO_* flags are defined in blk_types.h */
#include <linux/blk_types.h>
#if 0
#include <linux/uio.h>
#endif

#define BIO_MAX_VECS        256U

/*
 * bio_set is used to allow other portions of the IO system to
 * allocate their own private memory pools for bio and iovec structures.
 * These memory pools in turn all allocate from the bio_slab
 * and the bvec_slabs[].
 */
#define BIO_POOL_SIZE 2

#define BIO_INLINE_VECS 4

enum {
    BIOSET_NEED_BVECS = BIT(0),
    BIOSET_NEED_RESCUER = BIT(1),
    BIOSET_PERCPU_CACHE = BIT(2),
};

/*
 * bio flags
 */
enum {
    BIO_NO_PAGE_REF,    /* don't put release vec pages */
    BIO_CLONED,     /* doesn't own data */
    BIO_BOUNCED,        /* bio is a bounce bio */
    BIO_WORKINGSET,     /* contains userspace workingset pages */
    BIO_QUIET,      /* Make BIO Quiet */
    BIO_CHAIN,      /* chained bio, ->bi_remaining in effect */
    BIO_REFFED,     /* bio has elevated ->bi_cnt */
    BIO_THROTTLED,      /* This bio has already been subjected to
                 * throttling rules. Don't do it again. */
    BIO_TRACE_COMPLETION,   /* bio_endio() should trace the final completion
                 * of this bio. */
    BIO_CGROUP_ACCT,    /* has been accounted to a cgroup */
    BIO_QOS_THROTTLED,  /* bio went through rq_qos throttle path */
    BIO_QOS_MERGED,     /* but went through rq_qos merge path */
    BIO_REMAPPED,
    BIO_ZONE_WRITE_LOCKED,  /* Owns a zoned device zone write lock */
    BIO_PERCPU_CACHE,   /* can participate in per-cpu alloc cache */
    BIO_FLAG_LAST
};

/*
 * BIO list management for use by remapping drivers (e.g. DM or MD) and loop.
 *
 * A bio_list anchors a singly-linked list of bios chained through the bi_next
 * member of the bio.  The bio_list also caches the last list member to allow
 * fast access to the tail.
 */
struct bio_list {
    struct bio *head;
    struct bio *tail;
};

static inline int bio_list_empty(const struct bio_list *bl)
{
    return bl->head == NULL;
}

struct bio_set {
    struct kmem_cache *bio_slab;
    unsigned int front_pad;

    /*
     * per-cpu bio alloc cache
     */
    struct bio_alloc_cache __percpu *cache;

    mempool_t bio_pool;
    mempool_t bvec_pool;

    unsigned int back_pad;
    /*
     * Deadlock avoidance for stacking block drivers: see comments in
     * bio_alloc_bioset() for details
     */
    spinlock_t      rescue_lock;
    struct bio_list     rescue_list;
#if 0
    struct work_struct  rescue_work;
    struct workqueue_struct *rescue_workqueue;

    /*
     * Hot un-plug notifier for the per-cpu cache, if used
     */
    struct hlist_node cpuhp_dead;
#endif
};

struct bio *
bio_alloc_bioset(struct block_device *bdev, unsigned short nr_vecs,
                 unsigned int opf, gfp_t gfp_mask,
                 struct bio_set *bs);

extern struct bio_set fs_bio_set;

static inline struct bio *
bio_alloc(struct block_device *bdev, unsigned short nr_vecs,
          unsigned int opf, gfp_t gfp_mask)
{
    return bio_alloc_bioset(bdev, nr_vecs, opf, gfp_mask, &fs_bio_set);
}

static inline void bio_list_init(struct bio_list *bl)
{
    bl->head = bl->tail = NULL;
}

int bio_add_page(struct bio *, struct page *, unsigned len, unsigned off);
bool bio_add_folio(struct bio *, struct folio *, size_t len, size_t off);

static inline bool bio_flagged(struct bio *bio, unsigned int bit)
{
    return (bio->bi_flags & (1U << bit)) != 0;
}

static inline void bio_set_flag(struct bio *bio, unsigned int bit)
{
    bio->bi_flags |= (1U << bit);
}

static inline void bio_clear_flag(struct bio *bio, unsigned int bit)
{
    bio->bi_flags &= ~(1U << bit);
}

extern void bio_put(struct bio *);

void guard_bio_eod(struct bio *bio);

void submit_bio(struct bio *bio);

extern void bio_endio(struct bio *);

/*
 * Check whether this bio carries any data or not. A NULL bio is allowed.
 */
static inline bool bio_has_data(struct bio *bio)
{
    if (bio &&
        bio->bi_iter.bi_size &&
        bio_op(bio) != REQ_OP_DISCARD &&
        bio_op(bio) != REQ_OP_SECURE_ERASE &&
        bio_op(bio) != REQ_OP_WRITE_ZEROES)
        return true;

    return false;
}

#endif /* __LINUX_BIO_H */
