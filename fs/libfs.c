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
 * Retaining negative dentries for an in-memory filesystem just wastes
 * memory and lookup time: arrange for them to be deleted immediately.
 */
int always_delete_dentry(const struct dentry *dentry)
{
    return 1;
}
EXPORT_SYMBOL(always_delete_dentry);

const struct dentry_operations simple_dentry_operations = {
    .d_delete = always_delete_dentry,
};
EXPORT_SYMBOL(simple_dentry_operations);

/*
 * Lookup the data. This is trivial - if the dentry didn't already
 * exist, we know it is negative.  Set d_op to delete negative dentries.
 */
struct dentry *simple_lookup(struct inode *dir, struct dentry *dentry,
                             unsigned int flags)
{
    if (dentry->d_name.len > NAME_MAX)
        return ERR_PTR(-ENAMETOOLONG);
    if (!dentry->d_sb->s_d_op)
        d_set_d_op(dentry, &simple_dentry_operations);
    d_add(dentry, NULL);
    return NULL;
}
EXPORT_SYMBOL(simple_lookup);

static int simple_readpage(struct file *file, struct page *page)
{
#if 0
    clear_highpage(page);
    flush_dcache_page(page);
    SetPageUptodate(page);
    unlock_page(page);
#endif
    panic("%s: END!\n", __func__);
    return 0;
}

int simple_write_begin(struct file *file, struct address_space *mapping,
                       loff_t pos, unsigned len, unsigned flags,
                       struct page **pagep, void **fsdata)
{
    panic("%s: END!\n", __func__);
}

/**
 * simple_write_end - .write_end helper for non-block-device FSes
 * @file: See .write_end of address_space_operations
 * @mapping:        "
 * @pos:        "
 * @len:        "
 * @copied:         "
 * @page:       "
 * @fsdata:         "
 *
 * simple_write_end does the minimum needed for updating a page after writing is
 * done. It has the same API signature as the .write_end of
 * address_space_operations vector. So it can just be set onto .write_end for
 * FSes that don't need any other processing. i_mutex is assumed to be held.
 * Block based filesystems should use generic_write_end().
 * NOTE: Even though i_size might get updated by this function, mark_inode_dirty
 * is not called, so a filesystem that actually does store data in .write_inode
 * should extend on what's done here with a call to mark_inode_dirty() in the
 * case that i_size has changed.
 *
 * Use *ONLY* with simple_readpage()
 */
static int simple_write_end(struct file *file, struct address_space *mapping,
                            loff_t pos, unsigned len, unsigned copied,
                            struct page *page, void *fsdata)
{
    panic("%s: END!\n", __func__);
}

/*
 * Provides ramfs-style behavior: data in the pagecache, but no writeback.
 */
const struct address_space_operations ram_aops = {
    .readpage       = simple_readpage,
    .write_begin    = simple_write_begin,
    .write_end      = simple_write_end,
    .dirty_folio    = noop_dirty_folio,
};
EXPORT_SYMBOL(ram_aops);

int simple_link(struct dentry *old_dentry,
                struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = d_inode(old_dentry);

    //inode->i_ctime = dir->i_ctime = dir->i_mtime = current_time(inode);
    inc_nlink(inode);
    ihold(inode);
    dget(dentry);
    d_instantiate(dentry, inode);
    return 0;
}
EXPORT_SYMBOL(simple_link);

int simple_unlink(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = d_inode(dentry);

#if 0
    inode->i_ctime = dir->i_ctime = dir->i_mtime = current_time(inode);
    drop_nlink(inode);
    dput(dentry);
#endif
    panic("%s: END!\n", __func__);
    return 0;
}
EXPORT_SYMBOL(simple_unlink);

int simple_empty(struct dentry *dentry)
{
    struct dentry *child;
    int ret = 0;

    spin_lock(&dentry->d_lock);
    list_for_each_entry(child, &dentry->d_subdirs, d_child) {
        spin_lock_nested(&child->d_lock, DENTRY_D_LOCK_NESTED);
        if (simple_positive(child)) {
            spin_unlock(&child->d_lock);
            goto out;
        }
        spin_unlock(&child->d_lock);
    }
    ret = 1;
out:
    spin_unlock(&dentry->d_lock);
    return ret;
}
EXPORT_SYMBOL(simple_empty);

int simple_rmdir(struct inode *dir, struct dentry *dentry)
{
    if (!simple_empty(dentry))
        return -ENOTEMPTY;

#if 0
    drop_nlink(d_inode(dentry));
    simple_unlink(dir, dentry);
    drop_nlink(dir);
#endif
    panic("%s: END!\n", __func__);
    return 0;
}
EXPORT_SYMBOL(simple_rmdir);

int simple_rename(struct user_namespace *mnt_userns, struct inode *old_dir,
                  struct dentry *old_dentry, struct inode *new_dir,
                  struct dentry *new_dentry, unsigned int flags)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(simple_rename);
