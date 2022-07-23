// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1991, 1992 Linus Torvalds
 * Copyright (C) 1994,      Karl Keyte: Added support for disk statistics
 * Elevator latency, (C) 2000  Andrea Arcangeli <andrea@suse.de> SuSE
 * Queue request tables / lock, selectable elevator, Jens Axboe <axboe@suse.de>
 * kernel-doc documentation started by NeilBrown <neilb@cse.unsw.edu.au>
 *  -  July2000
 * bio rewrite, highmem i/o, etc, Jens Axboe <axboe@suse.de> - may 2001
 */

/*
 * This handles all read/write requests to block devices
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#if 0
#include <linux/blk-pm.h>
#include <linux/blk-integrity.h>
#endif
#include <linux/highmem.h>
#include <linux/mm.h>
#if 0
#include <linux/pagemap.h>
#include <linux/kernel_stat.h>
#endif
#include <linux/string.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#if 0
#include <linux/task_io_accounting_ops.h>
#include <linux/fault-inject.h>
#include <linux/list_sort.h>
#include <linux/delay.h>
#include <linux/ratelimit.h>
#include <linux/pm_runtime.h>
#include <linux/t10-pi.h>
#include <linux/debugfs.h>
#include <linux/bpf.h>
#include <linux/psi.h>
#include <linux/part_stat.h>
#include <linux/sched/sysctl.h>
#include <linux/blk-crypto.h>
#endif
#include <linux/blk-mq.h>
#include <linux/idr.h>

#include "blk.h"
#if 0
#include "blk-mq-sched.h"
#include "blk-pm.h"
#include "blk-cgroup.h"
#include "blk-throttle.h"
#endif

DEFINE_IDA(blk_queue_ida);

/*
 * For queue allocation
 */
struct kmem_cache *blk_requestq_cachep;
struct kmem_cache *blk_requestq_srcu_cachep;

/**
 * blk_queue_flag_set - atomically set a queue flag
 * @flag: flag to be set
 * @q: request queue
 */
void blk_queue_flag_set(unsigned int flag, struct request_queue *q)
{
    set_bit(flag, &q->queue_flags);
}
EXPORT_SYMBOL(blk_queue_flag_set);

/**
 * blk_queue_flag_clear - atomically clear a queue flag
 * @flag: flag to be cleared
 * @q: request queue
 */
void blk_queue_flag_clear(unsigned int flag, struct request_queue *q)
{
    clear_bit(flag, &q->queue_flags);
}
EXPORT_SYMBOL(blk_queue_flag_clear);

/**
 * blk_cleanup_queue - shutdown a request queue
 * @q: request queue to shutdown
 *
 * Mark @q DYING, drain all pending requests, mark @q DEAD, destroy and
 * put it.  All future requests will be failed immediately with -ENODEV.
 *
 * Context: can sleep
 */
void blk_cleanup_queue(struct request_queue *q)
{
    panic("%s: END!\n", __func__);
}

struct request_queue *blk_alloc_queue(int node_id, bool alloc_srcu)
{
    struct request_queue *q;
    int ret;

    q = kmem_cache_alloc_node(blk_get_queue_kmem_cache(alloc_srcu),
                              GFP_KERNEL | __GFP_ZERO, node_id);
    if (!q)
        return NULL;

    if (alloc_srcu) {
        panic("%s: alloc_srcu(%d)!\n", __func__, alloc_srcu);
#if 0
        blk_queue_flag_set(QUEUE_FLAG_HAS_SRCU, q);
        if (init_srcu_struct(q->srcu) != 0)
            goto fail_q;
#endif
    }

    q->last_merge = NULL;

    q->id = ida_simple_get(&blk_queue_ida, 0, 0, GFP_KERNEL);
    if (q->id < 0)
        goto fail_srcu;

#if 0
    ret = bioset_init(&q->bio_split, BIO_POOL_SIZE, 0, 0);
    if (ret)
        goto fail_id;

    q->stats = blk_alloc_queue_stats();
    if (!q->stats)
        goto fail_split;

    q->node = node_id;

    atomic_set(&q->nr_active_requests_shared_tags, 0);

    timer_setup(&q->timeout, blk_rq_timed_out_timer, 0);
    INIT_WORK(&q->timeout_work, blk_timeout_work);
    INIT_LIST_HEAD(&q->icq_list);

    kobject_init(&q->kobj, &blk_queue_ktype);

    mutex_init(&q->debugfs_mutex);
    mutex_init(&q->sysfs_lock);
    mutex_init(&q->sysfs_dir_lock);
    spin_lock_init(&q->queue_lock);

    init_waitqueue_head(&q->mq_freeze_wq);
    mutex_init(&q->mq_freeze_lock);

    /*
     * Init percpu_ref in atomic mode so that it's faster to shutdown.
     * See blk_register_queue() for details.
     */
    if (percpu_ref_init(&q->q_usage_counter,
                blk_queue_usage_counter_release,
                PERCPU_REF_INIT_ATOMIC, GFP_KERNEL))
        goto fail_stats;

    blk_queue_dma_alignment(q, 511);
    blk_set_default_limits(&q->limits);
    q->nr_requests = BLKDEV_DEFAULT_RQ;
#endif

    return q;

 fail_stats:
#if 0
    blk_free_queue_stats(q->stats);
#endif
 fail_split:
#if 0
    bioset_exit(&q->bio_split);
#endif
 fail_id:
#if 0
    ida_simple_remove(&blk_queue_ida, q->id);
#endif
 fail_srcu:
#if 0
    if (alloc_srcu)
        cleanup_srcu_struct(q->srcu);
#endif
 fail_q:
    kmem_cache_free(blk_get_queue_kmem_cache(alloc_srcu), q);
    return NULL;
}

/**
 * blk_get_queue - increment the request_queue refcount
 * @q: the request_queue structure to increment the refcount for
 *
 * Increment the refcount of the request_queue kobject.
 *
 * Context: Any context.
 */
bool blk_get_queue(struct request_queue *q)
{
    if (likely(!blk_queue_dying(q))) {
        __blk_get_queue(q);
        return true;
    }

    return false;
}
EXPORT_SYMBOL(blk_get_queue);

/*
 * Helper to implement file_operations.iopoll.  Requires the bio to be stored
 * in iocb->private, and cleared before freeing the bio.
 */
int iocb_bio_iopoll(struct kiocb *kiocb, struct io_comp_batch *iob,
                    unsigned int flags)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(iocb_bio_iopoll);


int __init blk_dev_init(void)
{
    BUILD_BUG_ON(REQ_OP_LAST >= (1 << REQ_OP_BITS));
    BUILD_BUG_ON(REQ_OP_BITS + REQ_FLAG_BITS > 8 *
                 sizeof_field(struct request, cmd_flags));
    BUILD_BUG_ON(REQ_OP_BITS + REQ_FLAG_BITS > 8 *
            sizeof_field(struct bio, bi_opf));
    BUILD_BUG_ON(ALIGN(offsetof(struct request_queue, srcu),
               __alignof__(struct request_queue)) !=
             sizeof(struct request_queue));

#if 0
    /* used for unplugging and affects IO latency/throughput - HIGHPRI */
    kblockd_workqueue = alloc_workqueue("kblockd",
                        WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
    if (!kblockd_workqueue)
        panic("Failed to create kblockd\n");
#endif

    blk_requestq_cachep =
        kmem_cache_create("request_queue", sizeof(struct request_queue), 0,
                          SLAB_PANIC, NULL);

    blk_requestq_srcu_cachep =
        kmem_cache_create("request_queue_srcu",
                          sizeof(struct request_queue) +
                          sizeof(struct srcu_struct),
                          0, SLAB_PANIC, NULL);

#if 0
    blk_debugfs_root = debugfs_create_dir("block", NULL);
#endif

    return 0;
}
