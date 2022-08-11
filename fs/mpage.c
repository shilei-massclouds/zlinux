// SPDX-License-Identifier: GPL-2.0
/*
 * fs/mpage.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * Contains functions related to preparing and submitting BIOs which contain
 * multiple pagecache pages.
 *
 * 15May2002    Andrew Morton
 *      Initial version
 * 27Jun2002    axboe@suse.de
 *      use bio_add_page() to build bio's just the right size
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <linux/gfp.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/prefetch.h>
#include <linux/mpage.h>
#include <linux/mm_inline.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include "internal.h"

struct mpage_readpage_args {
    struct bio *bio;
    struct page *page;
    unsigned int nr_pages;
    bool is_readahead;
    sector_t last_block_in_bio;
    struct buffer_head map_bh;
    unsigned long first_logical_block;
    get_block_t *get_block;
};

/*
 * I/O completion handler for multipage BIOs.
 *
 * The mpage code never puts partial pages into a BIO (except for end-of-file).
 * If a page does not map to a contiguous run of blocks then it simply falls
 * back to block_read_full_page().
 *
 * Why is this?  If a page's completion depends on a number of different BIOs
 * which can complete in any order (or at the same time) then determining the
 * status of that page is hard.  See end_buffer_async_read() for the details.
 * There is no point in duplicating all that complexity.
 */
static void mpage_end_io(struct bio *bio)
{
    struct bio_vec *bv;
    struct bvec_iter_all iter_all;

    bio_for_each_segment_all(bv, bio, iter_all) {
        struct page *page = bv->bv_page;
        page_endio(page, bio_op(bio), blk_status_to_errno(bio->bi_status));
    }

    bio_put(bio);
}

static struct bio *mpage_bio_submit(struct bio *bio)
{
    bio->bi_end_io = mpage_end_io;
    guard_bio_eod(bio);
    submit_bio(bio);
    return NULL;
}

/*
 * support function for mpage_readahead.  The fs supplied get_block might
 * return an up to date buffer.  This is used to map that buffer into
 * the page, which allows readpage to avoid triggering a duplicate call
 * to get_block.
 *
 * The idea is to avoid adding buffers to pages that don't already have
 * them.  So when the buffer is up to date and the page size == block size,
 * this marks the page up to date instead of adding new buffers.
 */
static void
map_buffer_to_page(struct page *page, struct buffer_head *bh, int page_block)
{
    struct inode *inode = page->mapping->host;
    struct buffer_head *page_bh, *head;
    int block = 0;

    if (!page_has_buffers(page)) {
        /*
         * don't make any buffers if there is only one buffer on
         * the page and the page just needs to be set up to date
         */
        if (inode->i_blkbits == PAGE_SHIFT && buffer_uptodate(bh)) {
            SetPageUptodate(page);
            return;
        }
        create_empty_buffers(page, i_blocksize(inode), 0);
    }

    panic("%s: END!\n", __func__);
}

/*
 * This is the worker routine which does all the work of mapping the disk
 * blocks and constructs largest possible bios, submits them for IO if the
 * blocks are not contiguous on the disk.
 *
 * We pass a buffer_head back and forth and use its buffer_mapped() flag to
 * represent the validity of its disk mapping and to decide when to do the next
 * get_block() call.
 */
static struct bio *do_mpage_readpage(struct mpage_readpage_args *args)
{
    struct page *page = args->page;
    struct inode *inode = page->mapping->host;
    const unsigned blkbits = inode->i_blkbits;
    const unsigned blocks_per_page = PAGE_SIZE >> blkbits;
    const unsigned blocksize = 1 << blkbits;
    struct buffer_head *map_bh = &args->map_bh;
    sector_t block_in_file;
    sector_t last_block;
    sector_t last_block_in_file;
    sector_t blocks[MAX_BUF_PER_PAGE];
    unsigned page_block;
    unsigned first_hole = blocks_per_page;
    struct block_device *bdev = NULL;
    int length;
    int fully_mapped = 1;
    int op = REQ_OP_READ;
    unsigned nblocks;
    unsigned relative_block;
    gfp_t gfp = mapping_gfp_constraint(page->mapping, GFP_KERNEL);

    if (args->is_readahead) {
        op |= REQ_RAHEAD;
        gfp |= __GFP_NORETRY | __GFP_NOWARN;
    }

    if (page_has_buffers(page))
        goto confused;

    block_in_file = (sector_t)page->index << (PAGE_SHIFT - blkbits);
    last_block = block_in_file + args->nr_pages * blocks_per_page;
    last_block_in_file = (i_size_read(inode) + blocksize - 1) >> blkbits;
    if (last_block > last_block_in_file)
        last_block = last_block_in_file;
    page_block = 0;

    /*
     * Map blocks using the result from the previous get_blocks call first.
     */
    nblocks = map_bh->b_size >> blkbits;
    if (buffer_mapped(map_bh) && block_in_file > args->first_logical_block &&
        block_in_file < (args->first_logical_block + nblocks)) {
        unsigned map_offset = block_in_file - args->first_logical_block;
        unsigned last = nblocks - map_offset;

        for (relative_block = 0; ; relative_block++) {
            if (relative_block == last) {
                clear_buffer_mapped(map_bh);
                break;
            }
            if (page_block == blocks_per_page)
                break;
            blocks[page_block] =
                map_bh->b_blocknr + map_offset + relative_block;
            page_block++;
            block_in_file++;
        }
        bdev = map_bh->b_bdev;
    }

    /*
     * Then do more get_blocks calls until we are done with this page.
     */
    map_bh->b_page = page;
    while (page_block < blocks_per_page) {
        map_bh->b_state = 0;
        map_bh->b_size = 0;

        if (block_in_file < last_block) {
            map_bh->b_size = (last_block-block_in_file) << blkbits;
            if (args->get_block(inode, block_in_file, map_bh, 0))
                goto confused;
            args->first_logical_block = block_in_file;
        }

        if (!buffer_mapped(map_bh)) {
            fully_mapped = 0;
            if (first_hole == blocks_per_page)
                first_hole = page_block;
            page_block++;
            block_in_file++;
            continue;
        }

        /* some filesystems will copy data into the page during
         * the get_block call, in which case we don't want to
         * read it again.  map_buffer_to_page copies the data
         * we just collected from get_block into the page's buffers
         * so readpage doesn't have to repeat the get_block call
         */
        if (buffer_uptodate(map_bh)) {
            map_buffer_to_page(page, map_bh, page_block);
            goto confused;
        }

        if (first_hole != blocks_per_page)
            goto confused;      /* hole -> non-hole */

        /* Contiguous blocks? */
        if (page_block && blocks[page_block-1] != map_bh->b_blocknr-1)
            goto confused;
        nblocks = map_bh->b_size >> blkbits;
        for (relative_block = 0; ; relative_block++) {
            if (relative_block == nblocks) {
                clear_buffer_mapped(map_bh);
                break;
            } else if (page_block == blocks_per_page)
                break;
            blocks[page_block] = map_bh->b_blocknr+relative_block;
            page_block++;
            block_in_file++;
        }
        bdev = map_bh->b_bdev;
    }

    if (first_hole != blocks_per_page) {
        zero_user_segment(page, first_hole << blkbits, PAGE_SIZE);
        if (first_hole == 0) {
            SetPageUptodate(page);
            unlock_page(page);
            goto out;
        }
    } else if (fully_mapped) {
        SetPageMappedToDisk(page);
    }

    /*
     * This page will go to BIO.  Do we need to send this BIO off first?
     */
    if (args->bio && (args->last_block_in_bio != blocks[0] - 1))
        args->bio = mpage_bio_submit(args->bio);

 alloc_new:
    if (args->bio == NULL) {
        if (first_hole == blocks_per_page) {
            if (!bdev_read_page(bdev, blocks[0] << (blkbits - 9), page))
                goto out;
        }
        args->bio = bio_alloc(bdev, bio_max_segs(args->nr_pages), op, gfp);
        if (args->bio == NULL)
            goto confused;
        args->bio->bi_iter.bi_sector = blocks[0] << (blkbits - 9);
    }

    length = first_hole << blkbits;
    if (bio_add_page(args->bio, page, length, 0) < length) {
        args->bio = mpage_bio_submit(args->bio);
        goto alloc_new;
    }

    relative_block = block_in_file - args->first_logical_block;
    nblocks = map_bh->b_size >> blkbits;
    if ((buffer_boundary(map_bh) && relative_block == nblocks) ||
        (first_hole != blocks_per_page))
        args->bio = mpage_bio_submit(args->bio);
    else
        args->last_block_in_bio = blocks[blocks_per_page - 1];

 out:
    return args->bio;

 confused:
    if (args->bio)
        args->bio = mpage_bio_submit(args->bio);
    if (!PageUptodate(page))
        block_read_full_page(page, args->get_block);
    else
        unlock_page(page);
    goto out;
}

/*
 * This isn't called much at all
 */
int mpage_readpage(struct page *page, get_block_t get_block)
{
    struct mpage_readpage_args args = {
        .page = page,
        .nr_pages = 1,
        .get_block = get_block,
    };

    args.bio = do_mpage_readpage(&args);
    if (args.bio)
        mpage_bio_submit(args.bio);
    return 0;
}
EXPORT_SYMBOL(mpage_readpage);

/**
 * mpage_readahead - start reads against pages
 * @rac: Describes which pages to read.
 * @get_block: The filesystem's block mapper function.
 *
 * This function walks the pages and the blocks within each page, building and
 * emitting large BIOs.
 *
 * If anything unusual happens, such as:
 *
 * - encountering a page which has buffers
 * - encountering a page which has a non-hole after a hole
 * - encountering a page with non-contiguous blocks
 *
 * then this code just gives up and calls the buffer_head-based read function.
 * It does handle a page which has holes at the end - that is a common case:
 * the end-of-file on blocksize < PAGE_SIZE setups.
 *
 * BH_Boundary explanation:
 *
 * There is a problem.  The mpage read code assembles several pages, gets all
 * their disk mappings, and then submits them all.  That's fine, but obtaining
 * the disk mappings may require I/O.  Reads of indirect blocks, for example.
 *
 * So an mpage read of the first 16 blocks of an ext2 file will cause I/O to be
 * submitted in the following order:
 *
 *  12 0 1 2 3 4 5 6 7 8 9 10 11 13 14 15 16
 *
 * because the indirect block has to be read to get the mappings of blocks
 * 13,14,15,16.  Obviously, this impacts performance.
 *
 * So what we do it to allow the filesystem's get_block() function to set
 * BH_Boundary when it maps block 11.  BH_Boundary says: mapping of the block
 * after this one will require I/O against a block which is probably close to
 * this one.  So you should push what I/O you have currently accumulated.
 *
 * This all causes the disk requests to be issued in the correct order.
 */
void mpage_readahead(struct readahead_control *rac, get_block_t get_block)
{
    struct page *page;
    struct mpage_readpage_args args = {
        .get_block = get_block,
        .is_readahead = true,
    };

    while ((page = readahead_page(rac))) {
        prefetchw(&page->flags);
        args.page = page;
        args.nr_pages = readahead_count(rac);
        args.bio = do_mpage_readpage(&args);
        put_page(page);
    }
    if (args.bio)
        mpage_bio_submit(args.bio);
}
EXPORT_SYMBOL(mpage_readahead);
