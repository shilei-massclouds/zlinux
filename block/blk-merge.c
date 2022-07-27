// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to segment and merge handling
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
//#include <linux/blk-integrity.h>
#include <linux/scatterlist.h>
//#include <linux/part_stat.h>
//#include <linux/blk-cgroup.h>

#include "blk.h"
#include "blk-mq-sched.h"
//#include "blk-rq-qos.h"
//#include "blk-throttle.h"

/**
 * __blk_queue_split - split a bio and submit the second half
 * @q:       [in] request_queue new bio is being queued at
 * @bio:     [in, out] bio to be split
 * @nr_segs: [out] number of segments in the first bio
 *
 * Split a bio into two bios, chain the two bios, submit the second half and
 * store a pointer to the first half in *@bio. If the second bio is still too
 * big it will be split by a recursive call to this function. Since this
 * function may allocate a new bio from q->bio_split, it is the responsibility
 * of the caller to ensure that q->bio_split is only released after processing
 * of the split bio has finished.
 */
void __blk_queue_split(struct request_queue *q, struct bio **bio,
                       unsigned int *nr_segs)
{
    panic("%s: END!\n", __func__);
}

/**
 * blk_attempt_plug_merge - try to merge with %current's plugged list
 * @q: request_queue new bio is being queued at
 * @bio: new bio being queued
 * @nr_segs: number of segments in @bio
 * from the passed in @q already in the plug list
 *
 * Determine whether @bio being queued on @q can be merged with the previous
 * request on %current's plugged list.  Returns %true if merge was successful,
 * otherwise %false.
 *
 * Plugging coalesces IOs from the same issuer for the same purpose without
 * going through @q->queue_lock.  As such it's more of an issuing mechanism
 * than scheduling, and the request, while may have elvpriv data, is not
 * added on the elevator at this point.  In addition, we don't have
 * reliable access to the elevator outside queue lock.  Only check basic
 * merging parameters without querying the elevator.
 *
 * Caller must ensure !blk_queue_nomerges(q) beforehand.
 */
bool blk_attempt_plug_merge(struct request_queue *q, struct bio *bio,
                            unsigned int nr_segs)
{
    struct blk_plug *plug;
    struct request *rq;

    plug = blk_mq_plug(q, bio);
    if (!plug || rq_list_empty(plug->mq_list))
        return false;

#if 0
    rq_list_for_each(&plug->mq_list, rq) {
        if (rq->q == q) {
            if (blk_attempt_bio_merge(q, rq, bio, nr_segs, false) ==
                BIO_MERGE_OK)
                return true;
            break;
        }

        /*
         * Only keep iterating plug list for merges if we have multiple
         * queues
         */
        if (!plug->multiple_queues)
            break;
    }
#endif
    panic("%s: END!\n", __func__);
    return false;
}
