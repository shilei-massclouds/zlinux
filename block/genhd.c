// SPDX-License-Identifier: GPL-2.0
/*
 *  gendisk handling
 *
 * Portions Copyright (C) 2020 Christoph Hellwig
 */

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/kmod.h>
#if 0
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/pm_runtime.h>
#include <linux/badblocks.h>
#include <linux/part_stat.h>
#include "blk-throttle.h"
#endif
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include <linux/log2.h>

#include "blk.h"
#include "blk-mq-sched.h"
#if 0
#include "blk-rq-qos.h"
#include "blk-cgroup.h"
#endif

/*
 * Can be deleted altogether. Later.
 *
 */
#define BLKDEV_MAJOR_HASH_SIZE 255
static struct blk_major_name {
    struct blk_major_name *next;
    int major;
    char name[16];
    void (*probe)(dev_t devt);
} *major_names[BLKDEV_MAJOR_HASH_SIZE];
static DEFINE_MUTEX(major_names_lock);
static DEFINE_SPINLOCK(major_names_spinlock);

/* for extended dynamic devt allocation, currently only one major is used */
#define NR_EXT_DEVT (1 << MINORBITS)
static DEFINE_IDA(ext_devt_ida);

struct class block_class = {
    .name       = "block",
    //.dev_uevent = block_uevent,
};

const struct device_type disk_type = {
    .name       = "disk",
#if 0
    .groups     = disk_attr_groups,
    .release    = disk_release,
    .devnode    = block_devnode,
#endif
};

/*
 * Unique, monotonically increasing sequential number associated with block
 * devices instances (i.e. incremented each time a device is attached).
 * Associating uevents with block devices in userspace is difficult and racy:
 * the uevent netlink socket is lossy, and on slow and overloaded systems has
 * a very high latency.
 * Block devices do not have exclusive owners in userspace, any process can set
 * one up (e.g. loop devices). Moreover, device names can be reused (e.g. loop0
 * can be reused again and again).
 * A userspace process setting up a block device and watching for its events
 * cannot thus reliably tell whether an event relates to the device it just set
 * up or another earlier instance with the same name.
 * This sequential number allows userspace processes to solve this problem, and
 * uniquely associate an uevent to the lifetime to a device.
 */
static atomic64_t diskseq;

/* index in the above - for now: assume no multimajor ranges */
static inline int major_to_index(unsigned major)
{
    return major % BLKDEV_MAJOR_HASH_SIZE;
}

void inc_diskseq(struct gendisk *disk)
{
    disk->diskseq = atomic64_inc_return(&diskseq);
}

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

    disk->node_id = node_id;
    mutex_init(&disk->open_mutex);
    xa_init(&disk->part_tbl);
    if (xa_insert(&disk->part_tbl, 0, disk->part0, GFP_KERNEL))
        goto out_destroy_part_tbl;

#if 0
    rand_initialize_disk(disk);
#endif
    disk_to_dev(disk)->class = &block_class;
    disk_to_dev(disk)->type = &disk_type;
    device_initialize(disk_to_dev(disk));
    inc_diskseq(disk);
    q->disk = disk;

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
    i_size_write(bdev->bd_inode, (loff_t)sectors << SECTOR_SHIFT);
    bdev->bd_nr_sectors = sectors;
    spin_unlock(&bdev->bd_size_lock);
}
EXPORT_SYMBOL(set_capacity);

int blk_alloc_ext_minor(void)
{
    int idx;

    idx = ida_alloc_range(&ext_devt_ida, 0, NR_EXT_DEVT - 1, GFP_KERNEL);
    if (idx == -ENOSPC)
        return -EBUSY;
    return idx;
}

int disk_scan_partitions(struct gendisk *disk, fmode_t mode)
{
    struct block_device *bdev;

    if (disk->flags & (GENHD_FL_NO_PART | GENHD_FL_HIDDEN))
        return -EINVAL;
    if (disk->open_partitions)
        return -EBUSY;

    set_bit(GD_NEED_PART_SCAN, &disk->state);
    bdev = blkdev_get_by_dev(disk_devt(disk), mode, NULL);
    if (IS_ERR(bdev))
        return PTR_ERR(bdev);
    blkdev_put(bdev, mode);
    return 0;
}

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
    struct device *ddev = disk_to_dev(disk);
    int ret;

    /* Only makes sense for bio-based to set ->poll_bio */
    if (queue_is_mq(disk->queue) && disk->fops->poll_bio)
        return -EINVAL;

    /*
     * The disk queue should now be all set with enough information about
     * the device for the elevator code to pick an adequate default
     * elevator if one is needed, that is, for devices requesting queue
     * registration.
     */
    elevator_init_mq(disk->queue);

    /*
     * If the driver provides an explicit major number it also must provide
     * the number of minors numbers supported, and those will be used to
     * setup the gendisk.
     * Otherwise just allocate the device numbers for both the whole device
     * and all partitions from the extended dev_t space.
     */
    if (disk->major) {
        if (WARN_ON(!disk->minors))
            return -EINVAL;

        if (disk->minors > DISK_MAX_PARTS) {
            pr_err("block: can't allocate more than %d partitions\n",
                   DISK_MAX_PARTS);
            disk->minors = DISK_MAX_PARTS;
        }
        if (disk->first_minor + disk->minors > MINORMASK + 1)
            return -EINVAL;
    } else {
        if (WARN_ON(disk->minors))
            return -EINVAL;

        ret = blk_alloc_ext_minor();
        if (ret < 0)
            return ret;
        disk->major = BLOCK_EXT_MAJOR;
        disk->first_minor = ret;
    }

    /* delay uevents, until we scanned partition table */
    //dev_set_uevent_suppress(ddev, 1);

    ddev->parent = parent;
    //ddev->groups = groups;
    dev_set_name(ddev, "%s", disk->disk_name);
    if (!(disk->flags & GENHD_FL_HIDDEN))
        ddev->devt = MKDEV(disk->major, disk->first_minor);
    ret = device_add(ddev);
    if (ret)
        goto out_free_ext_minor;

#if 0
    ret = disk_alloc_events(disk);
    if (ret)
        goto out_device_del;

    if (!sysfs_deprecated) {
        ret = sysfs_create_link(block_depr, &ddev->kobj,
                                kobject_name(&ddev->kobj));
        if (ret)
            goto out_device_del;
    }

    /*
     * avoid probable deadlock caused by allocating memory with
     * GFP_KERNEL in runtime_resume callback of its all ancestor
     * devices
     */
    pm_runtime_set_memalloc_noio(ddev, true);

    ret = blk_integrity_add(disk);
    if (ret)
        goto out_del_block_link;
#endif

    disk->part0->bd_holder_dir =
        kobject_create_and_add("holders", &ddev->kobj);
    if (!disk->part0->bd_holder_dir) {
        ret = -ENOMEM;
        goto out_del_integrity;
    }

    disk->slave_dir = kobject_create_and_add("slaves", &ddev->kobj);
    if (!disk->slave_dir) {
        ret = -ENOMEM;
        goto out_put_holder_dir;
    }

#if 0
    ret = bd_register_pending_holders(disk);
    if (ret < 0)
        goto out_put_slave_dir;

    ret = blk_register_queue(disk);
    if (ret)
        goto out_put_slave_dir;
#endif

    if (!(disk->flags & GENHD_FL_HIDDEN)) {
        ret = bdi_register(disk->bdi, "%u:%u", disk->major, disk->first_minor);
        if (ret)
            goto out_unregister_queue;
        bdi_set_owner(disk->bdi, ddev);
#if 0
        ret = sysfs_create_link(&ddev->kobj, &disk->bdi->dev->kobj, "bdi");
        if (ret)
            goto out_unregister_bdi;
#endif

        bdev_add(disk->part0, ddev->devt);
        if (get_capacity(disk))
            disk_scan_partitions(disk, FMODE_READ);

#if 0
        /*
         * Announce the disk and partitions after all partitions are
         * created. (for hidden disks uevents remain suppressed forever)
         */
        dev_set_uevent_suppress(ddev, 0);
        disk_uevent(disk, KOBJ_ADD);
#endif
        panic("%s: GENHD_FL_HIDDEN\n", __func__);
    }

#if 0
    disk_update_readahead(disk);
    disk_add_events(disk);
#endif
    set_bit(GD_ADDED, &disk->state);
    return 0;

 out_unregister_bdi:
#if 0
    if (!(disk->flags & GENHD_FL_HIDDEN))
        bdi_unregister(disk->bdi);
#endif
 out_unregister_queue:
#if 0
    blk_unregister_queue(disk);
#endif
 out_put_slave_dir:
    kobject_put(disk->slave_dir);
 out_put_holder_dir:
    kobject_put(disk->part0->bd_holder_dir);
 out_del_integrity:
    //blk_integrity_del(disk);
 out_del_block_link:
#if 0
    if (!sysfs_deprecated)
        sysfs_remove_link(block_depr, dev_name(ddev));
#endif
 out_device_del:
    device_del(ddev);
 out_free_ext_minor:
#if 0
    if (disk->major == BLOCK_EXT_MAJOR)
        blk_free_ext_minor(disk->first_minor);
#endif
    return ret;
}
EXPORT_SYMBOL(device_add_disk);

/*
 * Set disk capacity and notify if the size is not currently zero and will not
 * be set to zero.  Returns true if a uevent was sent, otherwise false.
 */
bool set_capacity_and_notify(struct gendisk *disk, sector_t size)
{
    sector_t capacity = get_capacity(disk);
    char *envp[] = { "RESIZE=1", NULL };

    set_capacity(disk, size);

    /*
     * Only print a message and send a uevent if the gendisk is user visible
     * and alive.  This avoids spamming the log and udev when setting the
     * initial capacity during probing.
     */
    if (size == capacity ||
        !disk_live(disk) ||
        (disk->flags & GENHD_FL_HIDDEN))
        return false;

#if 0
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

dev_t blk_lookup_devt(const char *name, int partno)
{
    dev_t devt = MKDEV(0, 0);
    struct class_dev_iter iter;
    struct device *dev;

    class_dev_iter_init(&iter, &block_class, NULL, &disk_type);
    while ((dev = class_dev_iter_next(&iter))) {
        struct gendisk *disk = dev_to_disk(dev);

        if (strcmp(dev_name(dev), name))
            continue;

        if (partno < disk->minors) {
            /* We need to return the right devno, even
             * if the partition doesn't exist yet.
             */
            devt = MKDEV(MAJOR(dev->devt), MINOR(dev->devt) + partno);
        } else {
#if 0
            devt = part_devt(disk, partno);
            if (devt)
                break;
#endif
            panic("%s: big partno(%d)!\n", __func__, partno);
        }
    }
    class_dev_iter_exit(&iter);
    return devt;
}

static char *bdevt_str(dev_t devt, char *buf)
{
    if (MAJOR(devt) <= 0xff && MINOR(devt) <= 0xff) {
        char tbuf[BDEVT_SIZE];
        snprintf(tbuf, BDEVT_SIZE, "%02x%02x", MAJOR(devt), MINOR(devt));
        snprintf(buf, BDEVT_SIZE, "%-9s", tbuf);
    } else
        snprintf(buf, BDEVT_SIZE, "%03x:%05x", MAJOR(devt), MINOR(devt));

    return buf;
}

/*
 * print a full list of all partitions - intended for places where the root
 * filesystem can't be mounted and thus to give the victim some idea of what
 * went wrong
 */
void __init printk_all_partitions(void)
{
    struct class_dev_iter iter;
    struct device *dev;

    class_dev_iter_init(&iter, &block_class, NULL, &disk_type);
    while ((dev = class_dev_iter_next(&iter))) {
        struct gendisk *disk = dev_to_disk(dev);
        struct block_device *part;
        char devt_buf[BDEVT_SIZE];
        unsigned long idx;

        /*
         * Don't show empty devices or things that have been
         * suppressed
         */
        if (get_capacity(disk) == 0 || (disk->flags & GENHD_FL_HIDDEN))
            continue;

        /*
         * Note, unlike /proc/partitions, I am showing the numbers in
         * hex - the same format as the root= option takes.
         */
        rcu_read_lock();
        xa_for_each(&disk->part_tbl, idx, part) {
            if (!bdev_nr_sectors(part))
                continue;
            printk("%s%s %10llu %pg %s",
                   bdev_is_partition(part) ? "  " : "",
                   bdevt_str(part->bd_dev, devt_buf),
                   bdev_nr_sectors(part) >> 1, part,
                   part->bd_meta_info ?
                   part->bd_meta_info->uuid : "");
            if (bdev_is_partition(part))
                printk("\n");
            else if (dev->parent && dev->parent->driver)
                printk(" driver: %s\n", dev->parent->driver->name);
            else
                printk(" (driver?)\n");
        }
        rcu_read_unlock();
    }
    class_dev_iter_exit(&iter);
}

/**
 * __register_blkdev - register a new block device
 *
 * @major: the requested major device number [1..BLKDEV_MAJOR_MAX-1]. If
 *         @major = 0, try to allocate any unused major number.
 * @name: the name of the new block device as a zero terminated string
 * @probe: pre-devtmpfs / pre-udev callback used to create disks when their
 *     pre-created device node is accessed. When a probe call uses
 *     add_disk() and it fails the driver must cleanup resources. This
 *     interface may soon be removed.
 *
 * The @name must be unique within the system.
 *
 * The return value depends on the @major input parameter:
 *
 *  - if a major device number was requested in range [1..BLKDEV_MAJOR_MAX-1]
 *    then the function returns zero on success, or a negative error code
 *  - if any unused major number was requested with @major = 0 parameter
 *    then the return value is the allocated major number in range
 *    [1..BLKDEV_MAJOR_MAX-1] or a negative error code otherwise
 *
 * See Documentation/admin-guide/devices.txt for the list of allocated
 * major numbers.
 *
 * Use register_blkdev instead for any new code.
 */
int __register_blkdev(unsigned int major, const char *name,
                      void (*probe)(dev_t devt))
{
    struct blk_major_name **n, *p;
    int index, ret = 0;

    mutex_lock(&major_names_lock);

    /* temporary */
    if (major == 0) {
        for (index = ARRAY_SIZE(major_names)-1; index > 0; index--) {
            if (major_names[index] == NULL)
                break;
        }

        if (index == 0) {
            printk("%s: failed to get major for %s\n",
                   __func__, name);
            ret = -EBUSY;
            goto out;
        }
        major = index;
        ret = major;
    }

    if (major >= BLKDEV_MAJOR_MAX) {
        pr_err("%s: major requested (%u) is greater than "
               "the maximum (%u) for %s\n",
               __func__, major, BLKDEV_MAJOR_MAX-1, name);

        ret = -EINVAL;
        goto out;
    }

    p = kmalloc(sizeof(struct blk_major_name), GFP_KERNEL);
    if (p == NULL) {
        ret = -ENOMEM;
        goto out;
    }

    p->major = major;
    p->probe = probe;
    strlcpy(p->name, name, sizeof(p->name));
    p->next = NULL;
    index = major_to_index(major);

    spin_lock(&major_names_spinlock);
    for (n = &major_names[index]; *n; n = &(*n)->next) {
        if ((*n)->major == major)
            break;
    }
    if (!*n)
        *n = p;
    else
        ret = -EBUSY;
    spin_unlock(&major_names_spinlock);

    if (ret < 0) {
        printk("register_blkdev: cannot get major %u for %s\n",
               major, name);
        kfree(p);
    }

 out:
    mutex_unlock(&major_names_lock);
    return ret;
}

void blk_request_module(dev_t devt)
{
    unsigned int major = MAJOR(devt);
    struct blk_major_name **n;

    mutex_lock(&major_names_lock);
    for (n = &major_names[major_to_index(major)]; *n; n = &(*n)->next) {
        if ((*n)->major == major && (*n)->probe) {
            (*n)->probe(devt);
            mutex_unlock(&major_names_lock);
            return;
        }
    }
    mutex_unlock(&major_names_lock);

#if 0
    if (request_module("block-major-%d-%d", MAJOR(devt), MINOR(devt)) > 0)
        /* Make old-style 2.4 aliases work */
        request_module("block-major-%d", MAJOR(devt));
#endif
}

static int __init genhd_device_init(void)
{
    int error;

    block_class.dev_kobj = sysfs_dev_block_kobj;
    error = class_register(&block_class);
    if (unlikely(error))
        return error;

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
