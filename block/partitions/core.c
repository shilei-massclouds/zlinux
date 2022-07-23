// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1991-1998  Linus Torvalds
 * Re-organised Feb 1998 Russell King
 * Copyright (C) 2020 Christoph Hellwig
 */
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#if 0
#include <linux/blktrace_api.h>
#include <linux/raid/detect.h>
#include "check.h"
#endif

int bdev_disk_changed(struct gendisk *disk, bool invalidate)
{
    int ret = 0;

    if (!disk_live(disk))
        return -ENXIO;

 rescan:
    if (disk->open_partitions)
        return -EBUSY;
    sync_blockdev(disk->part0);
    invalidate_bdev(disk->part0);
    blk_drop_partitions(disk);

    clear_bit(GD_NEED_PART_SCAN, &disk->state);

    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(bdev_disk_changed);
