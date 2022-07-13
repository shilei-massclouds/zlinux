// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2001  Andrea Arcangeli <andrea@suse.de> SuSE
 *  Copyright (C) 2016 - 2020 Christoph Hellwig
 */

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#if 0
#include <linux/kmod.h>
#include <linux/major.h>
#include <linux/device_cgroup.h>
#include <linux/blk-integrity.h>
#endif
#include <linux/backing-dev.h>
#include <linux/module.h>
#if 0
#include <linux/blkpg.h>
#include <linux/buffer_head.h>
#endif
#include <linux/magic.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#if 0
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/part_stat.h>
#endif
#include <linux/uaccess.h>
#if 0
#include "../fs/internal.h"
#endif
#include "blk.h"

struct block_device *bdev_alloc(struct gendisk *disk, u8 partno)
{
    struct block_device *bdev;
    struct inode *inode;

#if 0
    inode = new_inode(blockdev_superblock);
    if (!inode)
        return NULL;
    inode->i_mode = S_IFBLK;
    inode->i_rdev = 0;
    inode->i_data.a_ops = &def_blk_aops;
    mapping_set_gfp_mask(&inode->i_data, GFP_USER);

    bdev = I_BDEV(inode);
    mutex_init(&bdev->bd_fsfreeze_mutex);
    spin_lock_init(&bdev->bd_size_lock);
    bdev->bd_partno = partno;
    bdev->bd_inode = inode;
    bdev->bd_queue = disk->queue;
    bdev->bd_stats = alloc_percpu(struct disk_stats);
    if (!bdev->bd_stats) {
        iput(inode);
        return NULL;
    }
#endif
    bdev->bd_disk = disk;
    return bdev;
}
