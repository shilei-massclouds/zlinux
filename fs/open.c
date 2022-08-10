// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/open.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
//#include <linux/fsnotify.h>
#include <linux/module.h>
//#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#if 0
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#endif
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
//#include <linux/personality.h>
#include <linux/pagemap.h>
//#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#if 0
#include <linux/audit.h>
#include <linux/falloc.h>
#include <linux/ima.h>
#include <linux/dnotify.h>
#endif
#include <linux/fs_struct.h>
#include <linux/compat.h>
#include <linux/mnt_idmapping.h>

#include "internal.h"

/*
 * Called when an inode is about to be open.
 * We use this to disallow opening large files on 32bit systems if
 * the caller didn't specify O_LARGEFILE.  On 64bit systems we force
 * on this flag in sys_open.
 */
int generic_file_open(struct inode *inode, struct file *filp)
{
    if (!(filp->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
        return -EOVERFLOW;
    return 0;
}
EXPORT_SYMBOL(generic_file_open);

static int do_dentry_open(struct file *f,
                          struct inode *inode,
                          int (*open)(struct inode *, struct file *))
{
    static const struct file_operations empty_fops = {};
    int error;

    path_get(&f->f_path);
    f->f_inode = inode;
    f->f_mapping = inode->i_mapping;
#if 0
    f->f_wb_err = filemap_sample_wb_err(f->f_mapping);
    f->f_sb_err = file_sample_sb_err(f);
#endif

    if (unlikely(f->f_flags & O_PATH)) {
        f->f_mode = FMODE_PATH | FMODE_OPENED;
        f->f_op = &empty_fops;
        return 0;
    }

    if (f->f_mode & FMODE_WRITE && !special_file(inode->i_mode)) {
#if 0
        error = get_write_access(inode);
        if (unlikely(error))
            goto cleanup_file;
        error = __mnt_want_write(f->f_path.mnt);
        if (unlikely(error)) {
            put_write_access(inode);
            goto cleanup_file;
        }
        f->f_mode |= FMODE_WRITER;
#endif
        panic("%s: FMODE_WRITE!\n", __func__);
    }

    /* POSIX.1-2008/SUSv4 Section XSI 2.9.7 */
    if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))
        f->f_mode |= FMODE_ATOMIC_POS;

    f->f_op = fops_get(inode->i_fop);
    if (WARN_ON(!f->f_op)) {
        error = -ENODEV;
        goto cleanup_all;
    }

#if 0
    error = break_lease(locks_inode(f), f->f_flags);
    if (error)
        goto cleanup_all;
#endif

    /* normally all 3 are set; ->open() can clear them if needed */
    f->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
    if (!open)
        open = f->f_op->open;
    if (open) {
        error = open(inode, f);
        if (error)
            goto cleanup_all;
    }
    f->f_mode |= FMODE_OPENED;
    if ((f->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
        i_readcount_inc(inode);
    if ((f->f_mode & FMODE_READ) &&
        likely(f->f_op->read || f->f_op->read_iter))
        f->f_mode |= FMODE_CAN_READ;
    if ((f->f_mode & FMODE_WRITE) &&
        likely(f->f_op->write || f->f_op->write_iter))
        f->f_mode |= FMODE_CAN_WRITE;

    f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

    file_ra_state_init(&f->f_ra, f->f_mapping->host->i_mapping);

    /* NB: we're sure to have correct a_ops only after f_op->open */
    if (f->f_flags & O_DIRECT) {
        if (!f->f_mapping->a_ops || !f->f_mapping->a_ops->direct_IO)
            return -EINVAL;
    }

    /*
     * XXX: Huge page cache doesn't support writing yet. Drop all page
     * cache for this file before processing writes.
     */
    if (f->f_mode & FMODE_WRITE) {
        panic("%s: FMODE_WRITE!\n", __func__);
    }

    return 0;

 cleanup_all:
    if (WARN_ON_ONCE(error > 0))
        error = -EINVAL;
    fops_put(f->f_op);
    if (f->f_mode & FMODE_WRITER) {
#if 0
        put_write_access(inode);
        __mnt_drop_write(f->f_path.mnt);
#endif
        panic("%s: FMODE_WRITER!\n", __func__);
    }
 cleanup_file:
    path_put(&f->f_path);
    f->f_path.mnt = NULL;
    f->f_path.dentry = NULL;
    f->f_inode = NULL;
    return error;
}

/**
 * vfs_open - open the file at the given path
 * @path: path to open
 * @file: newly allocated file with f_flag initialized
 * @cred: credentials to use
 */
int vfs_open(const struct path *path, struct file *file)
{
    file->f_path = *path;
    return do_dentry_open(file, d_backing_inode(path->dentry), NULL);
}
