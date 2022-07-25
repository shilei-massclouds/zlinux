// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 1991, 1992  Linus Torvalds
 * Copyright (C) 2001  Andrea Arcangeli <andrea@suse.de> SuSE
 * Copyright (C) 2016 - 2020 Christoph Hellwig
 */
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#if 0
#include <linux/mpage.h>
#include <linux/uio.h>
#endif
#include <linux/namei.h>
#if 0
#include <linux/task_io_accounting_ops.h>
#include <linux/falloc.h>
#include <linux/suspend.h>
#endif
#include <linux/fs.h>
#include <linux/module.h>
#include "blk.h"

static int blkdev_open(struct inode *inode, struct file *filp)
{
    panic("%s: END!\n", __func__);
}

static int blkdev_close(struct inode *inode, struct file *filp)
{
    panic("%s: END!\n", __func__);
}

/*
 * for a block special file file_inode(file)->i_size is zero
 * so we compute the size by hand (just as in block_read/write above)
 */
static loff_t blkdev_llseek(struct file *file, loff_t offset, int whence)
{
    panic("%s: END!\n", __func__);
}

static ssize_t blkdev_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    panic("%s: END!\n", __func__);
}

/*
 * Write data to the block device.  Only intended for the block device itself
 * and the raw driver which basically is a fake block device.
 *
 * Does not take i_mutex for the write and thus is not for general purpose
 * use.
 */
static ssize_t blkdev_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    panic("%s: END!\n", __func__);
}

static int blkdev_fsync(struct file *filp, loff_t start, loff_t end,
                        int datasync)
{
    panic("%s: END!\n", __func__);
}

static long blkdev_fallocate(struct file *file, int mode, loff_t start,
                             loff_t len)
{
    panic("%s: END!\n", __func__);
}

const struct file_operations def_blk_fops = {
    .open       = blkdev_open,
    .release    = blkdev_close,
    .llseek     = blkdev_llseek,
    .read_iter  = blkdev_read_iter,
    .write_iter = blkdev_write_iter,
    .iopoll     = iocb_bio_iopoll,
    .mmap       = generic_file_mmap,
    .fsync      = blkdev_fsync,
    .unlocked_ioctl = blkdev_ioctl,
    .splice_read    = generic_file_splice_read,
    .splice_write   = iter_file_splice_write,
    .fallocate  = blkdev_fallocate,
};

static int blkdev_writepage(struct page *page, struct writeback_control *wbc)
{
    //return block_write_full_page(page, blkdev_get_block, wbc);
    panic("%s: END!\n", __func__);
}

static int blkdev_get_block(struct inode *inode, sector_t iblock,
                            struct buffer_head *bh, int create)
{
    bh->b_bdev = I_BDEV(inode);
    bh->b_blocknr = iblock;
    set_buffer_mapped(bh);
    return 0;
}

static int blkdev_readpage(struct file *file, struct page *page)
{
    return block_read_full_page(page, blkdev_get_block);
}

static void blkdev_readahead(struct readahead_control *rac)
{
    //mpage_readahead(rac, blkdev_get_block);
    panic("%s: END!\n", __func__);
}

static int
blkdev_write_begin(struct file *file, struct address_space *mapping,
                   loff_t pos, unsigned len, unsigned flags,
                   struct page **pagep, void **fsdata)
{
    //return block_write_begin(mapping, pos, len, flags, pagep, blkdev_get_block);
    panic("%s: END!\n", __func__);
}

static int
blkdev_write_end(struct file *file, struct address_space *mapping,
                 loff_t pos, unsigned len, unsigned copied, struct page *page,
                 void *fsdata)
{
#if 0
    int ret;
    ret = block_write_end(file, mapping, pos, len, copied, page, fsdata);

    unlock_page(page);
    put_page(page);

    return ret;
#endif
    panic("%s: END!\n", __func__);
}

static int blkdev_writepages(struct address_space *mapping,
                             struct writeback_control *wbc)
{
    //return generic_writepages(mapping, wbc);
    panic("%s: END!\n", __func__);
}

static ssize_t blkdev_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
    panic("%s: END!\n", __func__);
}

const struct address_space_operations def_blk_aops = {
    .dirty_folio    = block_dirty_folio,
    .invalidate_folio = block_invalidate_folio,
    .readpage   = blkdev_readpage,
    .readahead  = blkdev_readahead,
    .writepage  = blkdev_writepage,
    .write_begin    = blkdev_write_begin,
    .write_end  = blkdev_write_end,
    .writepages = blkdev_writepages,
    .direct_IO  = blkdev_direct_IO,
    .migratepage    = buffer_migrate_page_norefs,
    .is_dirty_writeback = buffer_check_dirty_writeback,
};
