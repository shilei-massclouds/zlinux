// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2007 Jens Axboe <jens.axboe@oracle.com>
 *
 * Scatterlist handling helpers.
 */
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>

/**
 * sg_init_table - Initialize SG table
 * @sgl:       The SG table
 * @nents:     Number of entries in table
 *
 * Notes:
 *   If this is part of a chained sg table, sg_mark_end() should be
 *   used only on the last table part.
 *
 **/
void sg_init_table(struct scatterlist *sgl, unsigned int nents)
{
    memset(sgl, 0, sizeof(*sgl) * nents);
    sg_init_marker(sgl, nents);
}
EXPORT_SYMBOL(sg_init_table);

/**
 * sg_next - return the next scatterlist entry in a list
 * @sg:     The current sg entry
 *
 * Description:
 *   Usually the next entry will be @sg@ + 1, but if this sg element is part
 *   of a chained scatterlist, it could jump to the start of a new
 *   scatterlist array.
 *
 **/
struct scatterlist *sg_next(struct scatterlist *sg)
{
    if (sg_is_last(sg))
        return NULL;

    sg++;
    if (unlikely(sg_is_chain(sg)))
        sg = sg_chain_ptr(sg);

    return sg;
}
EXPORT_SYMBOL(sg_next);

/**
 * sg_init_one - Initialize a single entry sg list
 * @sg:      SG entry
 * @buf:     Virtual address for IO
 * @buflen:  IO length
 *
 **/
void sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen)
{
    sg_init_table(sg, 1);
    sg_set_buf(sg, buf, buflen);
}
EXPORT_SYMBOL(sg_init_one);

/**
 * __sg_alloc_table - Allocate and initialize an sg table with given allocator
 * @table:  The sg table header to use
 * @nents:  Number of entries in sg list
 * @max_ents:   The maximum number of entries the allocator returns per call
 * @nents_first_chunk: Number of entries int the (preallocated) first
 *  scatterlist chunk, 0 means no such preallocated chunk provided by user
 * @gfp_mask:   GFP allocation mask
 * @alloc_fn:   Allocator to use
 *
 * Description:
 *   This function returns a @table @nents long. The allocator is
 *   defined to return scatterlist chunks of maximum size @max_ents.
 *   Thus if @nents is bigger than @max_ents, the scatterlists will be
 *   chained in units of @max_ents.
 *
 * Notes:
 *   If this function returns non-0 (eg failure), the caller must call
 *   __sg_free_table() to cleanup any leftover allocations.
 *
 **/
int __sg_alloc_table(struct sg_table *table, unsigned int nents,
                     unsigned int max_ents, struct scatterlist *first_chunk,
                     unsigned int nents_first_chunk, gfp_t gfp_mask,
                     sg_alloc_fn *alloc_fn)
{
    struct scatterlist *sg, *prv;
    unsigned int left;
    unsigned curr_max_ents = nents_first_chunk ?: max_ents;
    unsigned prv_max_ents;

    memset(table, 0, sizeof(*table));

    if (nents == 0)
        return -EINVAL;

    left = nents;
    prv = NULL;
    do {
        unsigned int sg_size, alloc_size = left;

        if (alloc_size > curr_max_ents) {
            alloc_size = curr_max_ents;
            sg_size = alloc_size - 1;
        } else
            sg_size = alloc_size;

        left -= sg_size;

        if (first_chunk) {
            sg = first_chunk;
            first_chunk = NULL;
        } else {
            sg = alloc_fn(alloc_size, gfp_mask);
        }
        if (unlikely(!sg)) {
            /*
             * Adjust entry count to reflect that the last
             * entry of the previous table won't be used for
             * linkage.  Without this, sg_kfree() may get
             * confused.
             */
            if (prv)
                table->nents = ++table->orig_nents;

            return -ENOMEM;
        }

        sg_init_table(sg, alloc_size);
        table->nents = table->orig_nents += sg_size;

        /*
         * If this is the first mapping, assign the sg table header.
         * If this is not the first mapping, chain previous part.
         */
        if (prv)
            sg_chain(prv, prv_max_ents, sg);
        else
            table->sgl = sg;

        /*
         * If no more entries after this one, mark the end
         */
        if (!left)
            sg_mark_end(&sg[sg_size - 1]);

        prv = sg;
        prv_max_ents = curr_max_ents;
        curr_max_ents = max_ents;
    } while (left);

    return 0;
}
