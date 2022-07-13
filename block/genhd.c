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

    disk->part0 = bdev_alloc(disk, 0);
    if (!disk->part0)
        goto out_free_bdi;

#if 0
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

void set_capacity(struct gendisk *disk, sector_t sectors)
{
    struct block_device *bdev = disk->part0;

    spin_lock(&bdev->bd_size_lock);
    //i_size_write(bdev->bd_inode, (loff_t)sectors << SECTOR_SHIFT);
    bdev->bd_nr_sectors = sectors;
    spin_unlock(&bdev->bd_size_lock);
}
EXPORT_SYMBOL(set_capacity);

/**
 * device_add_disk - add disk information to kernel list
 * @parent: parent device for the disk
 * @disk: per-device partitioning information
 * @groups: Additional per-device sysfs groups
 *
 * This function registers the partitioning information in @disk
 * with the kernel.
 */
int __must_check device_add_disk(struct device *parent, struct gendisk *disk,
                                 const struct attribute_group **groups)

{
    panic("%s: END!\n", __func__);
}

/*
 * Set disk capacity and notify if the size is not currently zero and will not
 * be set to zero.  Returns true if a uevent was sent, otherwise false.
 */
bool set_capacity_and_notify(struct gendisk *disk, sector_t size)
{
    sector_t capacity = get_capacity(disk);
    char *envp[] = { "RESIZE=1", NULL };

    set_capacity(disk, size);

#if 0
    /*
     * Only print a message and send a uevent if the gendisk is user visible
     * and alive.  This avoids spamming the log and udev when setting the
     * initial capacity during probing.
     */
    if (size == capacity ||
        !disk_live(disk) ||
        (disk->flags & GENHD_FL_HIDDEN))
        return false;

    pr_info("%s: detected capacity change from %lld to %lld\n",
        disk->disk_name, capacity, size);

    /*
     * Historically we did not send a uevent for changes to/from an empty
     * device.
     */
    if (!capacity || !size)
        return false;
    kobject_uevent_env(&disk_to_dev(disk)->kobj, KOBJ_CHANGE, envp);
#endif
    panic("%s: END!\n", __func__);
    return true;
}
EXPORT_SYMBOL_GPL(set_capacity_and_notify);

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
