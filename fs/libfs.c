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

int dcache_dir_open(struct inode *inode, struct file *file)
{
#if 0
    file->private_data = d_alloc_cursor(file->f_path.dentry);

    return file->private_data ? 0 : -ENOMEM;
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(dcache_dir_open);

int dcache_dir_close(struct inode *inode, struct file *file)
{
    dput(file->private_data);
    return 0;
}
EXPORT_SYMBOL(dcache_dir_close);

loff_t dcache_dir_lseek(struct file *file, loff_t offset, int whence)
{
    panic("%s: END!\n", __func__);
}

ssize_t generic_read_dir(struct file *filp, char __user *buf, size_t siz,
                         loff_t *ppos)
{
    return -EISDIR;
}
EXPORT_SYMBOL(generic_read_dir);

/*
 * Directory is locked and all positive dentries in it are safe, since
 * for ramfs-type trees they can't go away without unlink() or rmdir(),
 * both impossible due to the lock on directory.
 */

int dcache_readdir(struct file *file, struct dir_context *ctx)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(dcache_readdir);

/*
 * No-op implementation of ->fsync for in-memory filesystems.
 */
int noop_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    return 0;
}
EXPORT_SYMBOL(noop_fsync);

const struct file_operations simple_dir_operations = {
    .open       = dcache_dir_open,
    .release    = dcache_dir_close,
    .llseek     = dcache_dir_lseek,
    .read       = generic_read_dir,
    .iterate_shared = dcache_readdir,
    .fsync      = noop_fsync,
};
EXPORT_SYMBOL(simple_dir_operations);

/*
 * Lookup the data. This is trivial - if the dentry didn't already
 * exist, we know it is negative.  Set d_op to delete negative dentries.
 */
struct dentry *simple_lookup(struct inode *dir, struct dentry *dentry,
                             unsigned int flags)
{
#if 0
    if (dentry->d_name.len > NAME_MAX)
        return ERR_PTR(-ENAMETOOLONG);
    if (!dentry->d_sb->s_d_op)
        d_set_d_op(dentry, &simple_dentry_operations);
    d_add(dentry, NULL);
#endif
    panic("%s: END!\n", __func__);
    return NULL;
}
EXPORT_SYMBOL(simple_lookup);
