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

static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(bdev_lock);
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
    return 0;
}

static int blkdev_get_part(struct block_device *part, fmode_t mode)
{
    panic("%s: END!\n", __func__);
}

/**
 * bd_may_claim - test whether a block device can be claimed
 * @bdev: block device of interest
 * @whole: whole block device containing @bdev, may equal @bdev
 * @holder: holder trying to claim @bdev
 *
 * Test whether @bdev can be claimed by @holder.
 *
 * CONTEXT:
 * spin_lock(&bdev_lock).
 *
 * RETURNS:
 * %true if @bdev can be claimed, %false otherwise.
 */
static bool bd_may_claim(struct block_device *bdev,
                         struct block_device *whole,
                         void *holder)
{
    if (bdev->bd_holder == holder)
        return true;     /* already a holder */
    else if (bdev->bd_holder != NULL)
        return false;    /* held by someone else */
    else if (whole == bdev)
        return true;     /* is a whole device which isn't held */

    else if (whole->bd_holder == bd_may_claim)
        return true;     /* is a partition of a device that is being partitioned */
    else if (whole->bd_holder != NULL)
        return false;    /* is a partition of a held device */
    else
        return true;     /* is a partition of an un-held device */
}

/**
 * bd_prepare_to_claim - claim a block device
 * @bdev: block device of interest
 * @holder: holder trying to claim @bdev
 *
 * Claim @bdev.  This function fails if @bdev is already claimed by another
 * holder and waits if another claiming is in progress. return, the caller
 * has ownership of bd_claiming and bd_holder[s].
 *
 * RETURNS:
 * 0 if @bdev can be claimed, -EBUSY otherwise.
 */
int bd_prepare_to_claim(struct block_device *bdev, void *holder)
{
    struct block_device *whole = bdev_whole(bdev);

    if (WARN_ON_ONCE(!holder))
        return -EINVAL;

 retry:
    spin_lock(&bdev_lock);
    /* if someone else claimed, fail */
    if (!bd_may_claim(bdev, whole, holder)) {
        spin_unlock(&bdev_lock);
        return -EBUSY;
    }

    /* if claiming is already in progress, wait for it to finish */
    if (whole->bd_claiming) {
        panic("%s: bd_claiming!\n", __func__);
    }

    /* yay, all mine */
    whole->bd_claiming = holder;
    spin_unlock(&bdev_lock);
    return 0;
}

static void bd_clear_claiming(struct block_device *whole, void *holder)
{
    /* tell others that we're done */
    BUG_ON(whole->bd_claiming != holder);
    whole->bd_claiming = NULL;
    wake_up_bit(&whole->bd_claiming, 0);
}

/**
 * bd_finish_claiming - finish claiming of a block device
 * @bdev: block device of interest
 * @holder: holder that has claimed @bdev
 *
 * Finish exclusive open of a block device. Mark the device as exlusively
 * open by the holder and wake up all waiters for exclusive open to finish.
 */
static void bd_finish_claiming(struct block_device *bdev, void *holder)
{
    struct block_device *whole = bdev_whole(bdev);

    spin_lock(&bdev_lock);
    BUG_ON(!bd_may_claim(bdev, whole, holder));
    /*
     * Note that for a whole device bd_holders will be incremented twice,
     * and bd_holder will be set to bd_may_claim before being set to holder
     */
    whole->bd_holders++;
    whole->bd_holder = bd_may_claim;
    bdev->bd_holders++;
    bdev->bd_holder = holder;
    bd_clear_claiming(whole, holder);
    spin_unlock(&bdev_lock);
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
        ret = bd_prepare_to_claim(bdev, holder);
        if (ret)
            goto put_blkdev;
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
    if (mode & FMODE_EXCL) {
        bd_finish_claiming(bdev, holder);

        /*
         * Block event polling for write claims if requested.  Any write
         * holder makes the write_holder state stick until all are
         * released.  This is good enough and tracking individual
         * writeable reference is too fragile given the way @mode is
         * used in blkdev_get/put().
         */
        if ((mode & FMODE_WRITE) && !bdev->bd_write_holder &&
            (disk->event_flags & DISK_EVENT_FLAG_BLOCK_ON_EXCL_WRITE)) {
            bdev->bd_write_holder = true;
            unblock_events = false;
        }
    }
    mutex_unlock(&disk->open_mutex);

#if 0
    if (unblock_events)
        disk_unblock_events(disk);
#endif
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

/* Kill _all_ buffers and pagecache , dirty or not.. */
static void kill_bdev(struct block_device *bdev)
{
    struct address_space *mapping = bdev->bd_inode->i_mapping;

    if (mapping_empty(mapping))
        return;

#if 0
    invalidate_bh_lrus();
    truncate_inode_pages(mapping, 0);
#endif
    panic("%s: END!\n", __func__);
}

int set_blocksize(struct block_device *bdev, int size)
{
    /* Size must be a power of two, and between 512 and PAGE_SIZE */
    if (size > PAGE_SIZE || size < 512 || !is_power_of_2(size))
        return -EINVAL;

    /* Size cannot be smaller than the size supported by the device */
    if (size < bdev_logical_block_size(bdev))
        return -EINVAL;

    /* Don't change the size if it is same as current */
    if (bdev->bd_inode->i_blkbits != blksize_bits(size)) {
        sync_blockdev(bdev);
        bdev->bd_inode->i_blkbits = blksize_bits(size);
        kill_bdev(bdev);
    }
    return 0;
}
EXPORT_SYMBOL(set_blocksize);

int sb_set_blocksize(struct super_block *sb, int size)
{
    if (set_blocksize(sb->s_bdev, size))
        return 0;
    /* If we get here, we know size is power of two
     * and it's value is between 512 and PAGE_SIZE */
    sb->s_blocksize = size;
    sb->s_blocksize_bits = blksize_bits(size);
    return sb->s_blocksize;
}
EXPORT_SYMBOL(sb_set_blocksize);

int sb_min_blocksize(struct super_block *sb, int size)
{
    int minsize = bdev_logical_block_size(sb->s_bdev);
    if (size < minsize)
        size = minsize;
    return sb_set_blocksize(sb, size);
}
EXPORT_SYMBOL(sb_min_blocksize);
