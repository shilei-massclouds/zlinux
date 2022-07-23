// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/ext2/super.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
//#include <linux/parser.h>
#include <linux/random.h>
//#include <linux/buffer_head.h>
#include <linux/exportfs.h>
#if 0
#include <linux/vfs.h>
#include <linux/seq_file.h>
#endif
#include <linux/mount.h>
#include <linux/log2.h>
//#include <linux/quotaops.h>
#include <linux/uaccess.h>
//#include <linux/dax.h>
//#include <linux/iversion.h>
#include "ext2.h"
#if 0
#include "xattr.h"
#include "acl.h"
#endif

static struct kmem_cache *ext2_inode_cachep;

static void init_once(void *foo)
{
    struct ext2_inode_info *ei = (struct ext2_inode_info *) foo;

    rwlock_init(&ei->i_meta_lock);
    mutex_init(&ei->truncate_mutex);
    inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
    ext2_inode_cachep =
        kmem_cache_create_usercopy("ext2_inode_cache",
                                   sizeof(struct ext2_inode_info), 0,
                                   (SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD|
                                    SLAB_ACCOUNT),
                                   offsetof(struct ext2_inode_info, i_data),
                                   sizeof_field(struct ext2_inode_info, i_data),
                                   init_once);
    if (ext2_inode_cachep == NULL)
        return -ENOMEM;
    return 0;
}

static void destroy_inodecache(void)
{
    /*
     * Make sure all delayed rcu free inodes are flushed before we
     * destroy cache.
     */
    //rcu_barrier();
    kmem_cache_destroy(ext2_inode_cachep);
}

static int ext2_fill_super(struct super_block *sb, void *data, int silent)
{
    panic("%s: END!\n", __func__);
}

static struct dentry *ext2_mount(struct file_system_type *fs_type,
                                 int flags, const char *dev_name, void *data)
{
    return mount_bdev(fs_type, flags, dev_name, data, ext2_fill_super);
}

static struct file_system_type ext2_fs_type = {
    .owner      = THIS_MODULE,
    .name       = "ext2",
    .mount      = ext2_mount,
    .kill_sb    = kill_block_super,
    .fs_flags   = FS_REQUIRES_DEV,
};

static int __init init_ext2_fs(void)
{
    int err;

    err = init_inodecache();
    if (err)
        return err;
    err = register_filesystem(&ext2_fs_type);
    if (err)
        goto out;
    return 0;
out:
    destroy_inodecache();
    return err;
}

static void __exit exit_ext2_fs(void)
{
    unregister_filesystem(&ext2_fs_type);
    destroy_inodecache();
}

module_init(init_ext2_fs)
module_exit(exit_ext2_fs)
