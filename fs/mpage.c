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

/*
 * This isn't called much at all
 */
int mpage_readpage(struct page *page, get_block_t get_block)
{
#if 0
    struct mpage_readpage_args args = {
        .page = page,
        .nr_pages = 1,
        .get_block = get_block,
    };

    args.bio = do_mpage_readpage(&args);
    if (args.bio)
        mpage_bio_submit(args.bio);
#endif
    panic("%s: END!\n", __func__);
    return 0;
}
EXPORT_SYMBOL(mpage_readpage);
