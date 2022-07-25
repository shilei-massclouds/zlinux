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
#include <linux/pseudo_fs.h>
#include <linux/mount.h>
#if 0
#include <linux/uio.h>
#include <linux/part_stat.h>
#endif
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/fs_context.h>
#if 0
#include "../fs/internal.h"
#endif
#include "blk.h"

struct super_block *blockdev_superblock __read_mostly;
EXPORT_SYMBOL_GPL(blockdev_superblock);

static struct kmem_cache * bdev_cachep __read_mostly;

struct bdev_inode {
    struct block_device bdev;
    struct inode vfs_inode;
};

static inline struct bdev_inode *BDEV_I(struct inode *inode)
{
    return container_of(inode, struct bdev_inode, vfs_inode);
}

struct block_device *I_BDEV(struct inode *inode)
{
    return &BDEV_I(inode)->bdev;
}
EXPORT_SYMBOL(I_BDEV);

static struct inode *bdev_alloc_inode(struct super_block *sb)
{
    struct bdev_inode *ei = alloc_inode_sb(sb, bdev_cachep, GFP_KERNEL);

    if (!ei)
        return NULL;
    memset(&ei->bdev, 0, sizeof(ei->bdev));
    return &ei->vfs_inode;
}

static const struct super_operations bdev_sops = {
    //.statfs         = simple_statfs,
    .alloc_inode    = bdev_alloc_inode,
#if 0
    .free_inode     = bdev_free_inode,
    .drop_inode     = generic_delete_inode,
    .evict_inode    = bdev_evict_inode,
#endif
};

static int bd_init_fs_context(struct fs_context *fc)
{
    struct pseudo_fs_context *ctx = init_pseudo(fc, BDEVFS_MAGIC);
    if (!ctx)
        return -ENOMEM;
    fc->s_iflags |= SB_I_CGROUPWB;
    ctx->ops = &bdev_sops;
    return 0;
}

static struct file_system_type bd_type = {
    .name = "bdev",
    .init_fs_context = bd_init_fs_context,
    .kill_sb = kill_anon_super,
};

static void init_once(void *data)
{
    struct bdev_inode *ei = data;

    inode_init_once(&ei->vfs_inode);
}

void __init bdev_cache_init(void)
{
    int err;
    static struct vfsmount *bd_mnt;

    bdev_cachep =
        kmem_cache_create("bdev_cache", sizeof(struct bdev_inode), 0,
                          (SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT|
                           SLAB_MEM_SPREAD|SLAB_ACCOUNT|SLAB_PANIC),
                          init_once);
    err = register_filesystem(&bd_type);
    if (err)
        panic("Cannot register bdev pseudo-fs");
    bd_mnt = kern_mount(&bd_type);
    if (IS_ERR(bd_mnt))
        panic("Cannot create bdev pseudo-fs");
    blockdev_superblock = bd_mnt->mnt_sb;   /* For writeback */
}

struct block_device *bdev_alloc(struct gendisk *disk, u8 partno)
{
    struct block_device *bdev;
    struct inode *inode;

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
    //bdev->bd_stats = alloc_percpu(struct disk_stats);
#if 0
    if (!bdev->bd_stats) {
        iput(inode);
        return NULL;
    }
#endif
    bdev->bd_disk = disk;
    return bdev;
}

/**
 * lookup_bdev() - Look up a struct block_device by name.
 * @pathname: Name of the block device in the filesystem.
 * @dev: Pointer to the block device's dev_t, if found.
 *
 * Lookup the block device's dev_t at @pathname in the current
 * namespace if possible and return it in @dev.
 *
 * Context: May sleep.
 * Return: 0 if succeeded, negative errno otherwise.
 */
int lookup_bdev(const char *pathname, dev_t *dev)
{
    struct inode *inode;
    struct path path;
    int error;

    if (!pathname || !*pathname)
        return -EINVAL;

    error = kern_path(pathname, LOOKUP_FOLLOW, &path);
    if (error)
        return error;

    inode = d_backing_inode(path.dentry);
    error = -ENOTBLK;
    if (!S_ISBLK(inode->i_mode))
        goto out_path_put;
    error = -EACCES;
    if (!may_open_dev(&path))
        goto out_path_put;

    *dev = inode->i_rdev;
    error = 0;

 out_path_put:
    path_put(&path);
    return error;
}

struct block_device *blkdev_get_no_open(dev_t dev)
{
    struct block_device *bdev;
    struct inode *inode;

    inode = ilookup(blockdev_superblock, dev);
    if (!inode) {
        blk_request_module(dev);
        inode = ilookup(blockdev_superblock, dev);
        if (inode)
            pr_warn_ratelimited("block device autoloading is deprecated and "
                                "will be removed.\n");
    }
    if (!inode)
        return NULL;

    /* switch from the inode reference to a device mode one: */
    bdev = &BDEV_I(inode)->bdev;
    if (!kobject_get_unless_zero(&bdev->bd_device.kobj))
        bdev = NULL;
    iput(inode);
    return bdev;
}

void blkdev_put_no_open(struct block_device *bdev)
{
    put_device(&bdev->bd_device);
}

static void set_init_blocksize(struct block_device *bdev)
{
    unsigned int bsize = bdev_logical_block_size(bdev);
    loff_t size = i_size_read(bdev->bd_inode);

    while (bsize < PAGE_SIZE) {
        if (size & bsize)
            break;
        bsize <<= 1;
    }
    bdev->bd_inode->i_blkbits = blksize_bits(bsize);
}

static int blkdev_get_whole(struct block_device *bdev, fmode_t mode)
{
    struct gendisk *disk = bdev->bd_disk;
    int ret;

    if (disk->fops->open) {
#if 0
        ret = disk->fops->open(bdev, mode);
        if (ret) {
            /* avoid ghost partitions on a removed medium */
            if (ret == -ENOMEDIUM &&
                 test_bit(GD_NEED_PART_SCAN, &disk->state))
                bdev_disk_changed(disk, true);
            return ret;
        }
#endif
        panic("%s: open!\n", __func__);
    }

    if (!bdev->bd_openers)
        set_init_blocksize(bdev);
    if (test_bit(GD_NEED_PART_SCAN, &disk->state))
        bdev_disk_changed(disk, false);
    bdev->bd_openers++;
    panic("%s: END!\n", __func__);
    return 0;
}

static int blkdev_get_part(struct block_device *part, fmode_t mode)
{
    panic("%s: END!\n", __func__);
}

/**
 * blkdev_get_by_dev - open a block device by device number
 * @dev: device number of block device to open
 * @mode: FMODE_* mask
 * @holder: exclusive holder identifier
 *
 * Open the block device described by device number @dev. If @mode includes
 * %FMODE_EXCL, the block device is opened with exclusive access.  Specifying
 * %FMODE_EXCL with a %NULL @holder is invalid.  Exclusive opens may nest for
 * the same @holder.
 *
 * Use this interface ONLY if you really do not have anything better - i.e. when
 * you are behind a truly sucky interface and all you are given is a device
 * number.  Everything else should use blkdev_get_by_path().
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * Reference to the block_device on success, ERR_PTR(-errno) on failure.
 */
struct block_device *blkdev_get_by_dev(dev_t dev, fmode_t mode, void *holder)
{
    bool unblock_events = true;
    struct block_device *bdev;
    struct gendisk *disk;
    int ret;

    bdev = blkdev_get_no_open(dev);
    if (!bdev)
        return ERR_PTR(-ENXIO);
    disk = bdev->bd_disk;

    if (mode & FMODE_EXCL) {
#if 0
        ret = bd_prepare_to_claim(bdev, holder);
        if (ret)
            goto put_blkdev;
#endif
        panic("%s: FMODE_EXCL!\n", __func__);
    }

    //disk_block_events(disk);

    mutex_lock(&disk->open_mutex);
    ret = -ENXIO;
    if (!disk_live(disk))
        goto abort_claiming;
    if (!try_module_get(disk->fops->owner))
        goto abort_claiming;
    if (bdev_is_partition(bdev))
        ret = blkdev_get_part(bdev, mode);
    else
        ret = blkdev_get_whole(bdev, mode);
    if (ret)
        goto put_module;

    panic("%s: dev_t(%x) END!\n", __func__, dev);
    return bdev;

 put_module:
    module_put(disk->fops->owner);
 abort_claiming:
    if (mode & FMODE_EXCL) {
        //bd_abort_claiming(bdev, holder);
        panic("%s: FMODE_EXCL!\n", __func__);
    }
    mutex_unlock(&disk->open_mutex);
    //disk_unblock_events(disk);
 put_blkdev:
    blkdev_put_no_open(bdev);
    return ERR_PTR(ret);
}

/**
 * blkdev_get_by_path - open a block device by name
 * @path: path to the block device to open
 * @mode: FMODE_* mask
 * @holder: exclusive holder identifier
 *
 * Open the block device described by the device file at @path.  If @mode
 * includes %FMODE_EXCL, the block device is opened with exclusive access.
 * Specifying %FMODE_EXCL with a %NULL @holder is invalid.  Exclusive opens may
 * nest for the same @holder.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * Reference to the block_device on success, ERR_PTR(-errno) on failure.
 */
struct block_device *
blkdev_get_by_path(const char *path, fmode_t mode, void *holder)
{
    struct block_device *bdev;
    dev_t dev;
    int error;

    error = lookup_bdev(path, &dev);
    if (error)
        return ERR_PTR(error);

    bdev = blkdev_get_by_dev(dev, mode, holder);
    if (!IS_ERR(bdev) && (mode & FMODE_WRITE) && bdev_read_only(bdev)) {
        blkdev_put(bdev, mode);
        return ERR_PTR(-EACCES);
    }

    return bdev;
}
EXPORT_SYMBOL(blkdev_get_by_path);

void bdev_add(struct block_device *bdev, dev_t dev)
{
    bdev->bd_dev = dev;
    bdev->bd_inode->i_rdev = dev;
    bdev->bd_inode->i_ino = dev;
    insert_inode_hash(bdev->bd_inode);
}

void blkdev_put(struct block_device *bdev, fmode_t mode)
{
    pr_warn("%s: NO Implementation!\n", __func__);
}
EXPORT_SYMBOL(blkdev_put);

/*
 * Write out and wait upon all the dirty data associated with a block
 * device via its mapping.  Does not take the superblock lock.
 */
int sync_blockdev(struct block_device *bdev)
{
    if (!bdev)
        return 0;
    return filemap_write_and_wait(bdev->bd_inode->i_mapping);
}
EXPORT_SYMBOL(sync_blockdev);

/* Invalidate clean unused buffers and pagecache. */
void invalidate_bdev(struct block_device *bdev)
{
    struct address_space *mapping = bdev->bd_inode->i_mapping;

    if (mapping->nrpages) {
#if 0
        invalidate_bh_lrus();
        lru_add_drain_all();    /* make sure all lru add caches are flushed */
        invalidate_mapping_pages(mapping, 0, -1);
#endif
        panic("%s: nrpages > 0 \n", __func__);
    }
}
EXPORT_SYMBOL(invalidate_bdev);
