// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to segment and merge handling
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/blk-integrity.h>
#include <linux/scatterlist.h>
#include <linux/blkdev.h>
#include <linux/part_stat.h>
//#include <linux/blk-cgroup.h>

#include "blk.h"
#include "blk-mq-sched.h"
#include "blk-cgroup.h"
#include "blk-rq-qos.h"
//#include "blk-throttle.h"

enum bio_merge_status {
    BIO_MERGE_OK,
    BIO_MERGE_NONE,
    BIO_MERGE_FAILED,
};

static inline unsigned
get_max_segment_size(const struct request_queue *q,
                     struct page *start_page,
                     unsigned long offset);

/*
 * Return the maximum number of sectors from the start of a bio that may be
 * submitted as a single request to a block device. If enough sectors remain,
 * align the end to the physical block size. Otherwise align the end to the
 * logical block size. This approach minimizes the number of non-aligned
 * requests that are submitted to a block device if the start of a bio is not
 * aligned to a physical block boundary.
 */
static inline unsigned get_max_io_size(struct request_queue *q,
                                       struct bio *bio)
{
    unsigned sectors = blk_max_size_offset(q, bio->bi_iter.bi_sector, 0);
    unsigned max_sectors = sectors;
    unsigned pbs = queue_physical_block_size(q) >> SECTOR_SHIFT;
    unsigned lbs = queue_logical_block_size(q) >> SECTOR_SHIFT;
    unsigned start_offset = bio->bi_iter.bi_sector & (pbs - 1);

    max_sectors += start_offset;
    max_sectors &= ~(pbs - 1);
    printk("%s: max_sectors(%d)\n", __func__, max_sectors);
    if (max_sectors > start_offset)
        return max_sectors - start_offset;

    printk("%s: 2 sectors(%d)\n", __func__, sectors);
    return sectors & ~(lbs - 1);
}

/**
 * bvec_split_segs - verify whether or not a bvec should be split in the middle
 * @q:        [in] request queue associated with the bio associated with @bv
 * @bv:       [in] bvec to examine
 * @nsegs:    [in,out] Number of segments in the bio being built. Incremented
 *            by the number of segments from @bv that may be appended to that
 *            bio without exceeding @max_segs
 * @sectors:  [in,out] Number of sectors in the bio being built. Incremented
 *            by the number of sectors from @bv that may be appended to that
 *            bio without exceeding @max_sectors
 * @max_segs: [in] upper bound for *@nsegs
 * @max_sectors: [in] upper bound for *@sectors
 *
 * When splitting a bio, it can happen that a bvec is encountered that is too
 * big to fit in a single segment and hence that it has to be split in the
 * middle. This function verifies whether or not that should happen. The value
 * %true is returned if and only if appending the entire @bv to a bio with
 * *@nsegs segments and *@sectors sectors would make that bio unacceptable for
 * the block driver.
 */
static bool bvec_split_segs(const struct request_queue *q,
                            const struct bio_vec *bv, unsigned *nsegs,
                            unsigned *sectors, unsigned max_segs,
                            unsigned max_sectors)
{
    unsigned max_len = (min(max_sectors, UINT_MAX >> 9) - *sectors) << 9;
    unsigned len = min(bv->bv_len, max_len);
    unsigned total_len = 0;
    unsigned seg_size = 0;

    while (len && *nsegs < max_segs) {
        seg_size = get_max_segment_size(q, bv->bv_page,
                                        bv->bv_offset + total_len);
        seg_size = min(seg_size, len);

        (*nsegs)++;
        total_len += seg_size;
        len -= seg_size;

        if ((bv->bv_offset + total_len) & queue_virt_boundary(q))
            break;
    }

    *sectors += total_len >> 9;

    /* tell the caller to split the bvec if it is too big to fit */
    return len > 0 || bv->bv_len > max_len;
}

/**
 * blk_bio_segment_split - split a bio in two bios
 * @q:    [in] request queue pointer
 * @bio:  [in] bio to be split
 * @bs:   [in] bio set to allocate the clone from
 * @segs: [out] number of segments in the bio with the first half of the sectors
 *
 * Clone @bio, update the bi_iter of the clone to represent the first sectors
 * of @bio and update @bio->bi_iter to represent the remaining sectors. The
 * following is guaranteed for the cloned bio:
 * - That it has at most get_max_io_size(@q, @bio) sectors.
 * - That it has at most queue_max_segments(@q) segments.
 *
 * Except for discard requests the cloned bio will point at the bi_io_vec of
 * the original bio. It is the responsibility of the caller to ensure that the
 * original bio is not freed before the cloned bio. The caller is also
 * responsible for ensuring that @bs is only destroyed after processing of the
 * split bio has finished.
 */
static struct bio *blk_bio_segment_split(struct request_queue *q,
                                         struct bio *bio,
                                         struct bio_set *bs,
                                         unsigned *segs)
{
    struct bio_vec bv, bvprv, *bvprvp = NULL;
    struct bvec_iter iter;
    unsigned nsegs = 0, sectors = 0;
    const unsigned max_sectors = get_max_io_size(q, bio);
    const unsigned max_segs = queue_max_segments(q);

    bio_for_each_bvec(bv, bio, iter) {
        /*
         * If the queue doesn't support SG gaps and adding this
         * offset would create a gap, disallow it.
         */
        if (bvprvp && bvec_gap_to_prev(q, bvprvp, bv.bv_offset))
            goto split;

        if (nsegs < max_segs && sectors + (bv.bv_len >> 9) <= max_sectors &&
            bv.bv_offset + bv.bv_len <= PAGE_SIZE) {
            nsegs++;
            sectors += bv.bv_len >> 9;
        } else if (bvec_split_segs(q, &bv, &nsegs, &sectors, max_segs,
                                   max_sectors)) {
            goto split;
        }

        bvprv = bv;
        bvprvp = &bvprv;
    }

    *segs = nsegs;
    return NULL;
 split:
    *segs = nsegs;

    /*
     * Bio splitting may cause subtle trouble such as hang when doing sync
     * iopoll in direct IO routine. Given performance gain of iopoll for
     * big IO can be trival, disable iopoll when split needed.
     */
    bio_clear_polled(bio);
    return bio_split(bio, sectors, GFP_NOIO, bs);
}

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
    struct bio *split = NULL;

    switch (bio_op(*bio)) {
    case REQ_OP_DISCARD:
    case REQ_OP_SECURE_ERASE:
        //split = blk_bio_discard_split(q, *bio, &q->bio_split, nr_segs);
        panic("%s: REQ_OP_SECURE_ERASE!\n", __func__);
        break;
    case REQ_OP_WRITE_ZEROES:
        //split = blk_bio_write_zeroes_split(q, *bio, &q->bio_split, nr_segs);
        panic("%s: REQ_OP_WRITE_ZEROES!\n", __func__);
        break;
    default:
        split = blk_bio_segment_split(q, *bio, &q->bio_split, nr_segs);
        break;
    }

    if (split) {
        /* there isn't chance to merge the splitted bio */
        split->bi_opf |= REQ_NOMERGE;

        bio_chain(split, *bio);
        submit_bio_noacct(*bio);
        *bio = split;
    }
}

bool blk_rq_merge_ok(struct request *rq, struct bio *bio)
{
    if (!rq_mergeable(rq) || !bio_mergeable(bio))
        return false;

    if (req_op(rq) != bio_op(bio))
        return false;

    /* different data direction or already started, don't merge */
    if (bio_data_dir(bio) != rq_data_dir(rq))
        return false;

    /* only merge integrity protected bio into ditto rq */
    if (blk_integrity_merge_bio(rq->q, rq, bio) == false)
        return false;

    if (rq->ioprio != bio_prio(bio))
        return false;

    return true;
}

enum elv_merge blk_try_merge(struct request *rq, struct bio *bio)
{
    if (blk_discard_mergable(rq))
        return ELEVATOR_DISCARD_MERGE;
    else if (blk_rq_pos(rq) + blk_rq_sectors(rq) == bio->bi_iter.bi_sector)
        return ELEVATOR_BACK_MERGE;
    else if (blk_rq_pos(rq) - bio_sectors(bio) == bio->bi_iter.bi_sector)
        return ELEVATOR_FRONT_MERGE;
    return ELEVATOR_NO_MERGE;
}

static inline bool bio_will_gap(struct request_queue *q,
        struct request *prev_rq, struct bio *prev, struct bio *next)
{
    struct bio_vec pb, nb;

    if (!bio_has_data(prev) || !queue_virt_boundary(q))
        return false;

    panic("%s: END!\n", __func__);
}

static inline
bool req_gap_back_merge(struct request *req, struct bio *bio)
{
    return bio_will_gap(req->q, req, req->biotail, bio);
}

static inline
unsigned int blk_rq_get_max_sectors(struct request *rq, sector_t offset)
{
    struct request_queue *q = rq->q;

    if (blk_rq_is_passthrough(rq))
        return q->limits.max_hw_sectors;

    if (!q->limits.chunk_sectors ||
        req_op(rq) == REQ_OP_DISCARD ||
        req_op(rq) == REQ_OP_SECURE_ERASE)
        return blk_queue_get_max_sectors(q, req_op(rq));

    return min(blk_max_size_offset(q, offset, 0),
            blk_queue_get_max_sectors(q, req_op(rq)));
}

static inline unsigned int blk_rq_get_max_segments(struct request *rq)
{
    if (req_op(rq) == REQ_OP_DISCARD)
        return queue_max_discard_segments(rq->q);
    return queue_max_segments(rq->q);
}

static inline
int ll_new_hw_segment(struct request *req, struct bio *bio,
                      unsigned int nr_phys_segs)
{
    if (!blk_cgroup_mergeable(req, bio))
        goto no_merge;

    if (blk_integrity_merge_bio(req->q, req, bio) == false)
        goto no_merge;

    /* discard request merge won't add new segment */
    if (req_op(req) == REQ_OP_DISCARD)
        return 1;

    if (req->nr_phys_segments + nr_phys_segs >
        blk_rq_get_max_segments(req))
        goto no_merge;

    /*
     * This will form the start of a new hw segment.  Bump both
     * counters.
     */
    req->nr_phys_segments += nr_phys_segs;
    return 1;

no_merge:
    req_set_nomerge(req->q, req);
    return 0;
}

int ll_back_merge_fn(struct request *req, struct bio *bio,
                     unsigned int nr_segs)
{
    if (req_gap_back_merge(req, bio))
        return 0;
    if (blk_integrity_rq(req) &&
        integrity_req_gap_back_merge(req, bio))
        return 0;
    if (!bio_crypt_ctx_back_mergeable(req, bio))
        return 0;
    if (blk_rq_sectors(req) + bio_sectors(bio) >
        blk_rq_get_max_sectors(req, blk_rq_pos(req))) {
        req_set_nomerge(req->q, req);
        return 0;
    }

    return ll_new_hw_segment(req, bio, nr_segs);
}

/**
 * blk_rq_set_mixed_merge - mark a request as mixed merge
 * @rq: request to mark as mixed merge
 *
 * Description:
 *     @rq is about to be mixed merged.  Make sure the attributes
 *     which can be mixed are set in each bio and mark @rq as mixed
 *     merged.
 */
void blk_rq_set_mixed_merge(struct request *rq)
{
    unsigned int ff = rq->cmd_flags & REQ_FAILFAST_MASK;
    struct bio *bio;

    if (rq->rq_flags & RQF_MIXED_MERGE)
        return;

    /*
     * @rq will no longer represent mixable attributes for all the
     * contained bios.  It will just track those of the first one.
     * Distributes the attributs to each bio.
     */
    for (bio = rq->bio; bio; bio = bio->bi_next) {
        WARN_ON_ONCE((bio->bi_opf & REQ_FAILFAST_MASK) &&
                 (bio->bi_opf & REQ_FAILFAST_MASK) != ff);
        bio->bi_opf |= ff;
    }
    rq->rq_flags |= RQF_MIXED_MERGE;
}

static void blk_account_io_merge_bio(struct request *req)
{
    if (!blk_do_io_stat(req))
        return;

    part_stat_lock();
    printk("### ### %s: 1\n", __func__);
    part_stat_inc(req->part, merges[op_stat_group(req_op(req))]);
    printk("### ### %s: 2\n", __func__);
    part_stat_unlock();
}

static enum bio_merge_status
bio_attempt_back_merge(struct request *req, struct bio *bio,
                       unsigned int nr_segs)
{
    const int ff = bio->bi_opf & REQ_FAILFAST_MASK;

    if (!ll_back_merge_fn(req, bio, nr_segs))
        return BIO_MERGE_FAILED;

    rq_qos_merge(req->q, req, bio);

    if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
        blk_rq_set_mixed_merge(req);

    req->biotail->bi_next = bio;
    req->biotail = bio;
    req->__data_len += bio->bi_iter.bi_size;

    bio_crypt_free_ctx(bio);

    blk_account_io_merge_bio(req);
    return BIO_MERGE_OK;
}

static enum bio_merge_status
blk_attempt_bio_merge(struct request_queue *q,
                      struct request *rq,
                      struct bio *bio,
                      unsigned int nr_segs,
                      bool sched_allow_merge)
{
    if (!blk_rq_merge_ok(rq, bio))
        return BIO_MERGE_NONE;

    switch (blk_try_merge(rq, bio)) {
    case ELEVATOR_BACK_MERGE:
        if (!sched_allow_merge || blk_mq_sched_allow_merge(q, rq, bio))
            return bio_attempt_back_merge(rq, bio, nr_segs);
        break;
    case ELEVATOR_FRONT_MERGE:
#if 0
        if (!sched_allow_merge || blk_mq_sched_allow_merge(q, rq, bio))
            return bio_attempt_front_merge(rq, bio, nr_segs);
#endif
        panic("%s: ELEVATOR_FRONT_MERGE!\n", __func__);
        break;
    case ELEVATOR_DISCARD_MERGE:
        panic("%s: ELEVATOR_DISCARD_MERGE!\n", __func__);
        //return bio_attempt_discard_merge(q, rq, bio);
    default:
        return BIO_MERGE_NONE;
    }

    return BIO_MERGE_FAILED;
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
