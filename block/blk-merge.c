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

static inline struct scatterlist *
blk_next_sg(struct scatterlist **sg, struct scatterlist *sglist)
{
    if (!*sg)
        return sglist;

    /*
     * If the driver previously mapped a shorter list, we could see a
     * termination bit prematurely unless it fully inits the sg table
     * on each mapping. We KNOW that there must be more entries here
     * or the driver would be buggy, so force clear the termination bit
     * to avoid doing a full sg_init_table() in drivers for each command.
     */
    sg_unmark_end(*sg);
    return sg_next(*sg);
}

static inline int __blk_bvec_map_sg(struct bio_vec bv,
                                    struct scatterlist *sglist,
                                    struct scatterlist **sg)
{
    *sg = blk_next_sg(sg, sglist);
    sg_set_page(*sg, bv.bv_page, bv.bv_len, bv.bv_offset);
    return 1;
}

/* only try to merge bvecs into one sg if they are from two bios */
static inline bool
__blk_segment_map_sg_merge(struct request_queue *q, struct bio_vec *bvec,
                           struct bio_vec *bvprv, struct scatterlist **sg)
{

    int nbytes = bvec->bv_len;

    if (!*sg)
        return false;

    if ((*sg)->length + nbytes > queue_max_segment_size(q))
        return false;

    if (!biovec_phys_mergeable(q, bvprv, bvec))
        return false;

    (*sg)->length += nbytes;

    return true;
}

static inline unsigned
get_max_segment_size(const struct request_queue *q,
                     struct page *start_page,
                     unsigned long offset)
{
    unsigned long mask = queue_segment_boundary(q);

    offset = mask & (page_to_phys(start_page) + offset);

    /*
     * overflow may be triggered in case of zero page physical address
     * on 32bit arch, use queue's max segment size when that happens.
     */
    return min_not_zero(mask - offset + 1,
                        (unsigned long)queue_max_segment_size(q));
}

static unsigned
blk_bvec_map_sg(struct request_queue *q,
                struct bio_vec *bvec,
                struct scatterlist *sglist,
                struct scatterlist **sg)
{
    unsigned nbytes = bvec->bv_len;
    unsigned nsegs = 0, total = 0;

    while (nbytes > 0) {
        unsigned offset = bvec->bv_offset + total;
        unsigned len = min(get_max_segment_size(q, bvec->bv_page, offset),
                           nbytes);
        struct page *page = bvec->bv_page;

        /*
         * Unfortunately a fair number of drivers barf on scatterlists
         * that have an offset larger than PAGE_SIZE, despite other
         * subsystems dealing with that invariant just fine.  For now
         * stick to the legacy format where we never present those from
         * the block layer, but the code below should be removed once
         * these offenders (mostly MMC/SD drivers) are fixed.
         */
        page += (offset >> PAGE_SHIFT);
        offset &= ~PAGE_MASK;

        *sg = blk_next_sg(sg, sglist);
        sg_set_page(*sg, page, len, offset);

        total += len;
        nbytes -= len;
        nsegs++;
    }

    return nsegs;
}

static int __blk_bios_map_sg(struct request_queue *q, struct bio *bio,
                             struct scatterlist *sglist,
                             struct scatterlist **sg)
{
    struct bio_vec bvec, bvprv = { NULL };
    struct bvec_iter iter;
    int nsegs = 0;
    bool new_bio = false;

    for_each_bio(bio) {
        bio_for_each_bvec(bvec, bio, iter) {
            /*
             * Only try to merge bvecs from two bios given we
             * have done bio internal merge when adding pages
             * to bio
             */
            if (new_bio &&
                __blk_segment_map_sg_merge(q, &bvec, &bvprv, sg))
                goto next_bvec;

            if (bvec.bv_offset + bvec.bv_len <= PAGE_SIZE)
                nsegs += __blk_bvec_map_sg(bvec, sglist, sg);
            else
                nsegs += blk_bvec_map_sg(q, &bvec, sglist, sg);
 next_bvec:
            new_bio = false;
        }
        if (likely(bio->bi_iter.bi_size)) {
            bvprv = bvec;
            new_bio = true;
        }
    }

    return nsegs;
}

/*
 * map a request to scatterlist, return number of sg entries setup. Caller
 * must make sure sg can hold rq->nr_phys_segments entries
 */
int __blk_rq_map_sg(struct request_queue *q, struct request *rq,
                    struct scatterlist *sglist, struct scatterlist **last_sg)
{
    int nsegs = 0;

    if (rq->rq_flags & RQF_SPECIAL_PAYLOAD)
        nsegs = __blk_bvec_map_sg(rq->special_vec, sglist, last_sg);
    else if (rq->bio)
        nsegs = __blk_bios_map_sg(q, rq->bio, sglist, last_sg);

    if (*last_sg)
        sg_mark_end(*last_sg);

    /*
     * Something must have been wrong if the figured number of
     * segment is bigger than number of req's physical segments
     */
    WARN_ON(nsegs > blk_rq_nr_phys_segments(rq));

    return nsegs;
}
EXPORT_SYMBOL(__blk_rq_map_sg);
