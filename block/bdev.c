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
#include <linux/namei.h>
#include <linux/part_stat.h>
#endif
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
    //inode->i_data.a_ops = &def_blk_aops;
    //mapping_set_gfp_mask(&inode->i_data, GFP_USER);

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
