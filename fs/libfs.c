// SPDX-License-Identifier: GPL-2.0-only
/*
 *  fs/libfs.c
 *  Library for filesystems writers.
 */

#include <linux/blkdev.h>
#include <linux/export.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#if 0
#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/vfs.h>
#include <linux/quotaops.h>
#endif
#include <linux/mutex.h>
#if 0
#include <linux/namei.h>
#include <linux/exportfs.h>
#include <linux/buffer_head.h> /* sync_mapping_buffers */
#endif
#include <linux/writeback.h>
#include <linux/fs_context.h>
#include <linux/pseudo_fs.h>
#if 0
#include <linux/fsnotify.h>
#include <linux/unicode.h>
#include <linux/fscrypt.h>
#endif

#include <linux/uaccess.h>
#include <linux/statfs.h>

#include "internal.h"

static void pseudo_fs_free(struct fs_context *fc)
{
    kfree(fc->fs_private);
}

int simple_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    buf->f_type = dentry->d_sb->s_magic;
    buf->f_bsize = PAGE_SIZE;
    buf->f_namelen = NAME_MAX;
    return 0;
}
EXPORT_SYMBOL(simple_statfs);

static const struct super_operations simple_super_operations = {
    .statfs     = simple_statfs,
};

static int pseudo_fs_fill_super(struct super_block *s, struct fs_context *fc)
{
    struct pseudo_fs_context *ctx = fc->fs_private;
    struct inode *root;

    s->s_maxbytes = MAX_LFS_FILESIZE;
    s->s_blocksize = PAGE_SIZE;
    s->s_blocksize_bits = PAGE_SHIFT;
    s->s_magic = ctx->magic;
    s->s_op = ctx->ops ?: &simple_super_operations;
#if 0
    s->s_xattr = ctx->xattr;
#endif
    s->s_time_gran = 1;
    root = new_inode(s);
    if (!root)
        return -ENOMEM;

    /*
     * since this is the first inode, make it number 1. New inodes created
     * after this must take care not to collide with it (by passing
     * max_reserved of 1 to iunique).
     */
    root->i_ino = 1;
    root->i_mode = S_IFDIR | S_IRUSR | S_IWUSR;
    //root->i_atime = root->i_mtime = root->i_ctime = current_time(root);
    s->s_root = d_make_root(root);
    if (!s->s_root)
        return -ENOMEM;
    s->s_d_op = ctx->dops;
    return 0;
}

static int pseudo_fs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, pseudo_fs_fill_super);
}

static const struct fs_context_operations pseudo_fs_context_ops = {
    .free       = pseudo_fs_free,
    .get_tree   = pseudo_fs_get_tree,
};

/*
 * Common helper for pseudo-filesystems (sockfs, pipefs, bdev - stuff that
 * will never be mountable)
 */
struct pseudo_fs_context *
init_pseudo(struct fs_context *fc, unsigned long magic)
{
    struct pseudo_fs_context *ctx;

    ctx = kzalloc(sizeof(struct pseudo_fs_context), GFP_KERNEL);
    if (likely(ctx)) {
        ctx->magic = magic;
        fc->fs_private = ctx;
        fc->ops = &pseudo_fs_context_ops;
        fc->sb_flags |= SB_NOUSER;
        fc->global = true;
    }
    return ctx;
}
EXPORT_SYMBOL(init_pseudo);
