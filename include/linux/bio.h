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
#if 0
    struct bio_list     rescue_list;
    struct work_struct  rescue_work;
    struct workqueue_struct *rescue_workqueue;

    /*
     * Hot un-plug notifier for the per-cpu cache, if used
     */
    struct hlist_node cpuhp_dead;
#endif
};

#endif /* __LINUX_BIO_H */
