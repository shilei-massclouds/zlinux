// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to segment and merge handling
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
//#include <linux/blk-integrity.h>
#include <linux/scatterlist.h>
//#include <linux/part_stat.h>
//#include <linux/blk-cgroup.h>

#include "blk.h"
//#include "blk-mq-sched.h"
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
