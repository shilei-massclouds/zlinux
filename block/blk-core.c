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
#include <linux/pagemap.h>
#if 0
#include <linux/kernel_stat.h>
#endif
#include <linux/string.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/ratelimit.h>
#if 0
#include <linux/task_io_accounting_ops.h>
#include <linux/fault-inject.h>
#include <linux/list_sort.h>
#include <linux/delay.h>
#include <linux/pm_runtime.h>
#include <linux/t10-pi.h>
#include <linux/debugfs.h>
#include <linux/bpf.h>
#include <linux/psi.h>
#include <linux/sched/sysctl.h>
#endif
#include <linux/part_stat.h>
#include <linux/blk-crypto.h>
#include <linux/blk-mq.h>
#include <linux/idr.h>
#include <linux/percpu-refcount.h>

#include "blk.h"
#include "blk-mq.h"
#if 0
#include "blk-mq-sched.h"
#include "blk-pm.h"
#include "blk-cgroup.h"
#include "blk-throttle.h"
#endif

DEFINE_IDA(blk_queue_ida);

/*
 * Controlling structure to kblockd
 */
static struct workqueue_struct *kblockd_workqueue;

/*
 * For queue allocation
 */
struct kmem_cache *blk_requestq_cachep;
struct kmem_cache *blk_requestq_srcu_cachep;

static const struct {
    int     errno;
    const char  *name;
} blk_errors[] = {
    [BLK_STS_OK]        = { 0,      "" },
    [BLK_STS_NOTSUPP]   = { -EOPNOTSUPP, "operation not supported" },
    [BLK_STS_TIMEOUT]   = { -ETIMEDOUT, "timeout" },
    [BLK_STS_NOSPC]     = { -ENOSPC,    "critical space allocation" },
    [BLK_STS_TRANSPORT] = { -ENOLINK,   "recoverable transport" },
    [BLK_STS_TARGET]    = { -EREMOTEIO, "critical target" },
    [BLK_STS_NEXUS]     = { -EBADE, "critical nexus" },
    [BLK_STS_MEDIUM]    = { -ENODATA,   "critical medium" },
    [BLK_STS_PROTECTION]    = { -EILSEQ,    "protection" },
    [BLK_STS_RESOURCE]  = { -ENOMEM,    "kernel resource" },
    [BLK_STS_DEV_RESOURCE]  = { -EBUSY, "device resource" },
    [BLK_STS_AGAIN]     = { -EAGAIN,    "nonblocking retry" },
    [BLK_STS_OFFLINE]   = { -ENODEV,    "device offline" },

    /* device mapper special case, should not leak out: */
    [BLK_STS_DM_REQUEUE]    = { -EREMCHG, "dm internal retry" },

    /* zone device specific errors */
    [BLK_STS_ZONE_OPEN_RESOURCE]    = { -ETOOMANYREFS, "open zones exceeded" },
    [BLK_STS_ZONE_ACTIVE_RESOURCE]  = { -EOVERFLOW, "active zones exceeded" },

    /* everything else not covered above: */
    [BLK_STS_IOERR]     = { -EIO,   "I/O" },
};

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

static void blk_queue_usage_counter_release(struct percpu_ref *ref)
{
#if 0
    struct request_queue *q =
        container_of(ref, struct request_queue, q_usage_counter);

    wake_up_all(&q->mq_freeze_wq);
#endif
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

    ret = bioset_init(&q->bio_split, BIO_POOL_SIZE, 0, 0);
    if (ret)
        goto fail_id;

#if 0
    q->stats = blk_alloc_queue_stats();
    if (!q->stats)
        goto fail_split;
#endif

    q->node = node_id;

    atomic_set(&q->nr_active_requests_shared_tags, 0);

#if 0
    timer_setup(&q->timeout, blk_rq_timed_out_timer, 0);
    INIT_WORK(&q->timeout_work, blk_timeout_work);
#endif
    INIT_LIST_HEAD(&q->icq_list);

    kobject_init(&q->kobj, &blk_queue_ktype);

    mutex_init(&q->debugfs_mutex);
#if 0
    mutex_init(&q->sysfs_lock);
    mutex_init(&q->sysfs_dir_lock);
#endif
    spin_lock_init(&q->queue_lock);

#if 0
    init_waitqueue_head(&q->mq_freeze_wq);
    mutex_init(&q->mq_freeze_lock);
#endif

    /*
     * Init percpu_ref in atomic mode so that it's faster to shutdown.
     * See blk_register_queue() for details.
     */
    if (percpu_ref_init(&q->q_usage_counter,
                        blk_queue_usage_counter_release,
                        PERCPU_REF_INIT_ATOMIC, GFP_KERNEL))
        goto fail_stats;

#if 0
    blk_queue_dma_alignment(q, 511);
#endif
    blk_set_default_limits(&q->limits);
    q->nr_requests = BLKDEV_DEFAULT_RQ;

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

static inline bool bio_check_ro(struct bio *bio)
{
    if (op_is_write(bio_op(bio)) && bdev_read_only(bio->bi_bdev)) {
        if (op_is_flush(bio->bi_opf) && !bio_sectors(bio))
            return false;
        pr_warn("Trying to write to read-only block-device %pg\n",
                bio->bi_bdev);
        /* Older lvm-tools actually trigger this */
        return false;
    }

    return false;
}

static noinline int should_fail_bio(struct bio *bio)
{
    return 0;
}

/*
 * Check whether this bio extends beyond the end of the device or partition.
 * This may well happen - the kernel calls bread() without checking the size of
 * the device, e.g., when mounting a file system.
 */
static inline int bio_check_eod(struct bio *bio)
{
    sector_t maxsector = bdev_nr_sectors(bio->bi_bdev);
    unsigned int nr_sectors = bio_sectors(bio);

    if (nr_sectors && maxsector &&
        (nr_sectors > maxsector ||
         bio->bi_iter.bi_sector > maxsector - nr_sectors)) {
        pr_info_ratelimited("%s: attempt to access beyond end of device\n"
                            "%pg: rw=%d, want=%llu, limit=%llu\n",
                            current->comm,
                            bio->bi_bdev, bio->bi_opf,
                            bio_end_sector(bio), maxsector);
        return -EIO;
    }
    return 0;
}

/*
 * Remap block n of partition p to block n+start(p) of the disk.
 */
static int blk_partition_remap(struct bio *bio)
{
    panic("%s: END!\n", __func__);
}

/*
 * Check write append to a zoned block device.
 */
static inline blk_status_t
blk_check_zone_append(struct request_queue *q, struct bio *bio)
{
    panic("%s: END!\n", __func__);
}

void blk_queue_exit(struct request_queue *q)
{
    percpu_ref_put(&q->q_usage_counter);
}

static void __submit_bio(struct bio *bio)
{
    struct gendisk *disk = bio->bi_bdev->bd_disk;

    if (!disk->fops->submit_bio) {
        blk_mq_submit_bio(bio);
    } else if (likely(bio_queue_enter(bio) == 0)) {
        disk->fops->submit_bio(bio);
        blk_queue_exit(disk->queue);
    }
}

static void __submit_bio_noacct_mq(struct bio *bio)
{
    struct bio_list bio_list[2] = { };

    current->bio_list = bio_list;

    do {
        __submit_bio(bio);
    } while ((bio = bio_list_pop(&bio_list[0])));

    current->bio_list = NULL;
}

/*
 * The loop in this function may be a bit non-obvious, and so deserves some
 * explanation:
 *
 *  - Before entering the loop, bio->bi_next is NULL (as all callers ensure
 *    that), so we have a list with a single bio.
 *  - We pretend that we have just taken it off a longer list, so we assign
 *    bio_list to a pointer to the bio_list_on_stack, thus initialising the
 *    bio_list of new bios to be added.  ->submit_bio() may indeed add some more
 *    bios through a recursive call to submit_bio_noacct.  If it did, we find a
 *    non-NULL value in bio_list and re-enter the loop from the top.
 *  - In this case we really did just take the bio of the top of the list (no
 *    pretending) and so remove it from bio_list, and call into ->submit_bio()
 *    again.
 *
 * bio_list_on_stack[0] contains bios submitted by the current ->submit_bio.
 * bio_list_on_stack[1] contains bios that were submitted before the current
 *  ->submit_bio, but that haven't been processed yet.
 */
static void __submit_bio_noacct(struct bio *bio)
{
    panic("%s: END!\n", __func__);
}

void submit_bio_noacct_nocheck(struct bio *bio)
{
    /*
     * We only want one ->submit_bio to be active at a time, else stack
     * usage with stacked devices could be a problem.  Use current->bio_list
     * to collect a list of requests submited by a ->submit_bio method while
     * it is active, and then process them after it returned.
     */
    if (current->bio_list)
        bio_list_add(&current->bio_list[0], bio);
    else if (!bio->bi_bdev->bd_disk->fops->submit_bio)
        __submit_bio_noacct_mq(bio);
    else
        __submit_bio_noacct(bio);
}

int __bio_queue_enter(struct request_queue *q, struct bio *bio)
{
    panic("%s: END!\n", __func__);
}

static void flush_plug_callbacks(struct blk_plug *plug, bool from_schedule)
{
    LIST_HEAD(callbacks);

    while (!list_empty(&plug->cb_list)) {
        list_splice_init(&plug->cb_list, &callbacks);

        while (!list_empty(&callbacks)) {
            struct blk_plug_cb *cb = list_first_entry(&callbacks,
                                                      struct blk_plug_cb,
                                                      list);
            list_del(&cb->list);
            cb->callback(cb, from_schedule);
        }
    }
}

void __blk_flush_plug(struct blk_plug *plug, bool from_schedule)
{
    if (!list_empty(&plug->cb_list))
        flush_plug_callbacks(plug, from_schedule);
    if (!rq_list_empty(plug->mq_list))
        blk_mq_flush_plug_list(plug, from_schedule);
    /*
     * Unconditionally flush out cached requests, even if the unplug
     * event came from schedule. Since we know hold references to the
     * queue for cached requests, we don't want a blocked task holding
     * up a queue freeze/quiesce event.
     */
    if (unlikely(!rq_list_empty(plug->cached_rq)))
        blk_mq_free_plug_rqs(plug);
}

/**
 * submit_bio_noacct - re-submit a bio to the block device layer for I/O
 * @bio:  The bio describing the location in memory and on the device.
 *
 * This is a version of submit_bio() that shall only be used for I/O that is
 * resubmitted to lower level drivers by stacking block drivers.  All file
 * systems and other upper level users of the block layer should use
 * submit_bio() instead.
 */
void submit_bio_noacct(struct bio *bio)
{
    struct block_device *bdev = bio->bi_bdev;
    struct request_queue *q = bdev_get_queue(bdev);
    blk_status_t status = BLK_STS_IOERR;
    struct blk_plug *plug;

    might_sleep();

    plug = blk_mq_plug(q, bio);
    if (plug && plug->nowait)
        bio->bi_opf |= REQ_NOWAIT;

    /*
     * For a REQ_NOWAIT based request, return -EOPNOTSUPP
     * if queue does not support NOWAIT.
     */
    if ((bio->bi_opf & REQ_NOWAIT) && !blk_queue_nowait(q))
        goto not_supported;

    if (should_fail_bio(bio))
        goto end_io;
    if (unlikely(bio_check_ro(bio)))
        goto end_io;
    if (!bio_flagged(bio, BIO_REMAPPED)) {
        if (unlikely(bio_check_eod(bio)))
            goto end_io;
        if (bdev->bd_partno && unlikely(blk_partition_remap(bio)))
            goto end_io;
    }

    /*
     * Filter flush bio's early so that bio based drivers without flush
     * support don't have to worry about them.
     */
    if (op_is_flush(bio->bi_opf) && !test_bit(QUEUE_FLAG_WC, &q->queue_flags)) {
        bio->bi_opf &= ~(REQ_PREFLUSH | REQ_FUA);
        if (!bio_sectors(bio)) {
            status = BLK_STS_OK;
            goto end_io;
        }
    }

    if (!test_bit(QUEUE_FLAG_POLL, &q->queue_flags))
        bio_clear_polled(bio);

    switch (bio_op(bio)) {
    case REQ_OP_DISCARD:
        if (!blk_queue_discard(q))
            goto not_supported;
        break;
    case REQ_OP_SECURE_ERASE:
        if (!blk_queue_secure_erase(q))
            goto not_supported;
        break;
    case REQ_OP_ZONE_APPEND:
        status = blk_check_zone_append(q, bio);
        if (status != BLK_STS_OK)
            goto end_io;
        break;
    case REQ_OP_ZONE_RESET:
    case REQ_OP_ZONE_OPEN:
    case REQ_OP_ZONE_CLOSE:
    case REQ_OP_ZONE_FINISH:
        if (!blk_queue_is_zoned(q))
            goto not_supported;
        break;
    case REQ_OP_ZONE_RESET_ALL:
        if (!blk_queue_is_zoned(q) || !blk_queue_zone_resetall(q))
            goto not_supported;
        break;
    case REQ_OP_WRITE_ZEROES:
        if (!q->limits.max_write_zeroes_sectors)
            goto not_supported;
        break;
    default:
        break;
    }

    if (!bio_flagged(bio, BIO_TRACE_COMPLETION)) {
        /* Now that enqueuing has been traced, we need to trace
         * completion as well.
         */
        bio_set_flag(bio, BIO_TRACE_COMPLETION);
    }

    submit_bio_noacct_nocheck(bio);
    return;

 not_supported:
    status = BLK_STS_NOTSUPP;
 end_io:
    bio->bi_status = status;
    bio_endio(bio);
}

/**
 * submit_bio - submit a bio to the block device layer for I/O
 * @bio: The &struct bio which describes the I/O
 *
 * submit_bio() is used to submit I/O requests to block devices.  It is passed a
 * fully set up &struct bio that describes the I/O that needs to be done.  The
 * bio will be send to the device described by the bi_bdev field.
 *
 * The success/failure status of the request, along with notification of
 * completion, is delivered asynchronously through the ->bi_end_io() callback
 * in @bio.  The bio must NOT be touched by thecaller until ->bi_end_io() has
 * been called.
 */
void submit_bio(struct bio *bio)
{
#if 0
    /*
     * If it's a regular read/write or a barrier with data attached,
     * go through the normal accounting stuff before submission.
     */
    if (bio_has_data(bio)) {
       unsigned int count = bio_sectors(bio);

        if (op_is_write(bio_op(bio))) {
            count_vm_events(PGPGOUT, count);
        } else {
            task_io_account_read(bio->bi_iter.bi_size);
            count_vm_events(PGPGIN, count);
        }
    }
#endif

    /*
     * If we're reading data that is part of the userspace workingset, count
     * submission time as memory stall.  When the device is congested, or
     * the submitting cgroup IO-throttled, submission can be a significant
     * part of overall IO time.
     */
    if (unlikely(bio_op(bio) == REQ_OP_READ &&
        bio_flagged(bio, BIO_WORKINGSET))) {
#if 0
        unsigned long pflags;

        psi_memstall_enter(&pflags);
        submit_bio_noacct(bio);
        psi_memstall_leave(&pflags);
#endif
        panic("%s: REQ_OP_READ & BIO_WORKINGSET!\n", __func__);
        return;
    }

    submit_bio_noacct(bio);
}
EXPORT_SYMBOL(submit_bio);

const char *blk_status_to_str(blk_status_t status)
{
    int idx = (__force int)status;

    if (WARN_ON_ONCE(idx >= ARRAY_SIZE(blk_errors)))
        return "<null>";
    return blk_errors[idx].name;
}

#define REQ_OP_NAME(name) [REQ_OP_##name] = #name
static const char *const blk_op_name[] = {
    REQ_OP_NAME(READ),
    REQ_OP_NAME(WRITE),
    REQ_OP_NAME(FLUSH),
    REQ_OP_NAME(DISCARD),
    REQ_OP_NAME(SECURE_ERASE),
    REQ_OP_NAME(ZONE_RESET),
    REQ_OP_NAME(ZONE_RESET_ALL),
    REQ_OP_NAME(ZONE_OPEN),
    REQ_OP_NAME(ZONE_CLOSE),
    REQ_OP_NAME(ZONE_FINISH),
    REQ_OP_NAME(ZONE_APPEND),
    REQ_OP_NAME(WRITE_ZEROES),
    REQ_OP_NAME(DRV_IN),
    REQ_OP_NAME(DRV_OUT),
};
#undef REQ_OP_NAME

/**
 * blk_op_str - Return string XXX in the REQ_OP_XXX.
 * @op: REQ_OP_XXX.
 *
 * Description: Centralize block layer function to convert REQ_OP_XXX into
 * string format. Useful in the debugging and tracing bio or request. For
 * invalid REQ_OP_XXX it returns string "UNKNOWN".
 */
inline const char *blk_op_str(unsigned int op)
{
    const char *op_str = "UNKNOWN";

    if (op < ARRAY_SIZE(blk_op_name) && blk_op_name[op])
        op_str = blk_op_name[op];

    return op_str;
}
EXPORT_SYMBOL_GPL(blk_op_str);

/**
 * blk_queue_enter() - try to increase q->q_usage_counter
 * @q: request queue pointer
 * @flags: BLK_MQ_REQ_NOWAIT and/or BLK_MQ_REQ_PM
 */
int blk_queue_enter(struct request_queue *q, blk_mq_req_flags_t flags)
{
    const bool pm = flags & BLK_MQ_REQ_PM;

    while (!blk_try_enter_queue(q, pm)) {
        if (flags & BLK_MQ_REQ_NOWAIT)
            return -EBUSY;

        /*
         * read pair of barrier in blk_freeze_queue_start(), we need to
         * order reading __PERCPU_REF_DEAD flag of .q_usage_counter and
         * reading .mq_freeze_depth or queue dying flag, otherwise the
         * following wait may never return if the two reads are
         * reordered.
         */
        smp_rmb();
#if 0
        wait_event(q->mq_freeze_wq,
                   (!q->mq_freeze_depth && blk_pm_resume_queue(pm, q)) ||
                   blk_queue_dying(q));
        if (blk_queue_dying(q))
            return -ENODEV;
#endif
        panic("%s: !blk_try_enter_queue\n", __func__);
    }

    return 0;
}

int blk_status_to_errno(blk_status_t status)
{
    int idx = (__force int)status;

    if (WARN_ON_ONCE(idx >= ARRAY_SIZE(blk_errors)))
        return -EIO;
    return blk_errors[idx].errno;
}
EXPORT_SYMBOL_GPL(blk_status_to_errno);

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

    /* used for unplugging and affects IO latency/throughput - HIGHPRI */
    kblockd_workqueue = alloc_workqueue("kblockd",
                                        WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
    if (!kblockd_workqueue)
        panic("Failed to create kblockd\n");

    blk_requestq_cachep =
        kmem_cache_create("request_queue",
                          sizeof(struct request_queue), 0,
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

void blk_start_plug_nr_ios(struct blk_plug *plug, unsigned short nr_ios)
{
    struct task_struct *tsk = current;

    /*
     * If this is a nested plug, don't actually assign it.
     */
    if (tsk->plug)
        return;

    plug->mq_list = NULL;
    plug->cached_rq = NULL;
    plug->nr_ios = min_t(unsigned short, nr_ios, BLK_MAX_REQUEST_COUNT);
    plug->rq_count = 0;
    plug->multiple_queues = false;
    plug->has_elevator = false;
    plug->nowait = false;
    INIT_LIST_HEAD(&plug->cb_list);

    /*
     * Store ordering should not be needed here, since a potential
     * preempt will imply a full memory barrier
     */
    tsk->plug = plug;
}

/**
 * blk_start_plug - initialize blk_plug and track it inside the task_struct
 * @plug:   The &struct blk_plug that needs to be initialized
 *
 * Description:
 *   blk_start_plug() indicates to the block layer an intent by the caller
 *   to submit multiple I/O requests in a batch.  The block layer may use
 *   this hint to defer submitting I/Os from the caller until blk_finish_plug()
 *   is called.  However, the block layer may choose to submit requests
 *   before a call to blk_finish_plug() if the number of queued I/Os
 *   exceeds %BLK_MAX_REQUEST_COUNT, or if the size of the I/O is larger than
 *   %BLK_PLUG_FLUSH_SIZE.  The queued I/Os may also be submitted early if
 *   the task schedules (see below).
 *
 *   Tracking blk_plug inside the task_struct will help with auto-flushing the
 *   pending I/O should the task end up blocking between blk_start_plug() and
 *   blk_finish_plug(). This is important from a performance perspective, but
 *   also ensures that we don't deadlock. For instance, if the task is blocking
 *   for a memory allocation, memory reclaim could end up wanting to free a
 *   page belonging to that request that is currently residing in our private
 *   plug. By flushing the pending I/O when the process goes to sleep, we avoid
 *   this kind of deadlock.
 */
void blk_start_plug(struct blk_plug *plug)
{
    blk_start_plug_nr_ios(plug, 1);
}
EXPORT_SYMBOL(blk_start_plug);

/**
 * blk_finish_plug - mark the end of a batch of submitted I/O
 * @plug:   The &struct blk_plug passed to blk_start_plug()
 *
 * Description:
 * Indicate that a batch of I/O submissions is complete.  This function
 * must be paired with an initial call to blk_start_plug().  The intent
 * is to allow the block layer to optimize I/O submission.  See the
 * documentation for blk_start_plug() for more information.
 */
void blk_finish_plug(struct blk_plug *plug)
{
    if (plug == current->plug) {
        __blk_flush_plug(plug, false);
        current->plug = NULL;
    }
}
EXPORT_SYMBOL(blk_finish_plug);

int kblockd_mod_delayed_work_on(int cpu, struct delayed_work *dwork,
                                unsigned long delay)
{
    return mod_delayed_work_on(cpu, kblockd_workqueue, dwork, delay);
}
EXPORT_SYMBOL(kblockd_mod_delayed_work_on);

void update_io_ticks(struct block_device *part, unsigned long now,
                     bool end)
{
    unsigned long stamp;

 again:
    stamp = READ_ONCE(part->bd_stamp);
    if (unlikely(time_after(now, stamp))) {
        if (likely(cmpxchg(&part->bd_stamp, stamp, now) == stamp))
            __part_stat_add(part, io_ticks, end ? now - stamp : 1);
    }
    if (part->bd_partno) {
        part = bdev_whole(part);
        goto again;
    }
}
