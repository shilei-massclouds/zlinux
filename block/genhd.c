// SPDX-License-Identifier: GPL-2.0
/*
 *  gendisk handling
 *
 * Portions Copyright (C) 2020 Christoph Hellwig
 */

#include <linux/module.h>
#include <linux/ctype.h>
#if 0
#include <linux/fs.h>
#endif
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#if 0
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmod.h>
#include <linux/pm_runtime.h>
#include <linux/badblocks.h>
#include <linux/part_stat.h>
#include "blk-throttle.h"
#include <linux/major.h>
#endif
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include <linux/log2.h>

#include "blk.h"
#if 0
#include "blk-mq-sched.h"
#include "blk-rq-qos.h"
#include "blk-cgroup.h"
#endif

struct gendisk *__alloc_disk_node(struct request_queue *q, int node_id,
                                  struct lock_class_key *lkclass)
{
    struct gendisk *disk;

    if (!blk_get_queue(q))
        return NULL;

    disk = kzalloc_node(sizeof(struct gendisk), GFP_KERNEL, node_id);
    if (!disk)
        goto out_put_queue;

    disk->bdi = bdi_alloc(node_id);
    if (!disk->bdi)
        goto out_free_disk;

    /* bdev_alloc() might need the queue, set before the first call */
    disk->queue = q;

#if 0
    disk->part0 = bdev_alloc(disk, 0);
    if (!disk->part0)
        goto out_free_bdi;

    disk->node_id = node_id;
    mutex_init(&disk->open_mutex);
    xa_init(&disk->part_tbl);
    if (xa_insert(&disk->part_tbl, 0, disk->part0, GFP_KERNEL))
        goto out_destroy_part_tbl;

    if (blkcg_init_queue(q))
        goto out_erase_part0;

    rand_initialize_disk(disk);
    disk_to_dev(disk)->class = &block_class;
    disk_to_dev(disk)->type = &disk_type;
    device_initialize(disk_to_dev(disk));
    inc_diskseq(disk);
    q->disk = disk;
    lockdep_init_map(&disk->lockdep_map, "(bio completion)", lkclass, 0);
#endif

    //panic("%s: END!\n", __func__);
    return disk;

 out_erase_part0:
#if 0
    xa_erase(&disk->part_tbl, 0);
#endif
 out_destroy_part_tbl:
#if 0
    xa_destroy(&disk->part_tbl);
    disk->part0->bd_disk = NULL;
    iput(disk->part0->bd_inode);
#endif
 out_free_bdi:
#if 0
    bdi_put(disk->bdi);
#endif
 out_free_disk:
    kfree(disk);
 out_put_queue:
    //blk_put_queue(q);
    return NULL;
}

/**
 * set_disk_ro - set a gendisk read-only
 * @disk:   gendisk to operate on
 * @read_only:  %true to set the disk read-only, %false set the disk read/write
 *
 * This function is used to indicate whether a given disk device should have its
 * read-only flag set. set_disk_ro() is typically used by device drivers to
 * indicate whether the underlying physical device is write-protected.
 */
void set_disk_ro(struct gendisk *disk, bool read_only)
{
    if (read_only) {
        if (test_and_set_bit(GD_READ_ONLY, &disk->state))
            return;
    } else {
        if (!test_and_clear_bit(GD_READ_ONLY, &disk->state))
            return;
    }
    //set_disk_ro_uevent(disk, read_only);
}
EXPORT_SYMBOL(set_disk_ro);

static int __init genhd_device_init(void)
{
    int error;

#if 0
    block_class.dev_kobj = sysfs_dev_block_kobj;
    error = class_register(&block_class);
    if (unlikely(error))
        return error;
#endif
    blk_dev_init();

#if 0
    register_blkdev(BLOCK_EXT_MAJOR, "blkext");

    /* create top-level block dir */
    if (!sysfs_deprecated)
        block_depr = kobject_create_and_add("block", NULL);
#endif

    return 0;
}

subsys_initcall(genhd_device_init);
