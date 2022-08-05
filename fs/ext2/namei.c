// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ext2/namei.c
 *
 * Rewrite to pagecache. Almost all code had been changed, so blame me
 * if the things go wrong. Please, send bug reports to
 * viro@parcelfarce.linux.theplanet.co.uk
 *
 * Stuff here is basically a glue between the VFS and generic UNIXish
 * filesystem that keeps everything in pagecache. All knowledge of the
 * directory layout is in fs/ext2/dir.c - it turned out to be easily separatable
 * and it's easier to debug that way. In principle we might want to
 * generalize that a bit and turn it into a library. Or not.
 *
 * The only non-static object here is ext2_dir_inode_operations.
 *
 * TODO: get rid of kmap() use, add readahead.
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/pagemap.h>
//#include <linux/quotaops.h>
#include "ext2.h"
#if 0
#include "xattr.h"
#include "acl.h"
#endif

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int ext2_create(struct user_namespace *mnt_userns,
                       struct inode *dir, struct dentry *dentry,
                       umode_t mode, bool excl)
{
    panic("%s: END!\n", __func__);
}

static int ext2_tmpfile(struct user_namespace *mnt_userns, struct inode *dir,
                        struct dentry *dentry, umode_t mode)
{
    panic("%s: END!\n", __func__);
}

static int ext2_mknod(struct user_namespace * mnt_userns, struct inode * dir,
                      struct dentry *dentry, umode_t mode, dev_t rdev)
{
    panic("%s: END!\n", __func__);
}

static int ext2_symlink(struct user_namespace * mnt_userns, struct inode * dir,
                        struct dentry * dentry, const char * symname)
{
    panic("%s: END!\n", __func__);
}

static int ext2_link(struct dentry *old_dentry, struct inode *dir,
                     struct dentry *dentry)
{
    panic("%s: END!\n", __func__);
}

static int ext2_unlink(struct inode * dir, struct dentry *dentry)
{
    panic("%s: END!\n", __func__);
}

static int ext2_mkdir(struct user_namespace *mnt_userns,
                      struct inode *dir, struct dentry *dentry, umode_t mode)
{
    panic("%s: END!\n", __func__);
}

static int ext2_rmdir(struct inode * dir, struct dentry *dentry)
{
    panic("%s: END!\n", __func__);
}

static int ext2_rename(struct user_namespace *mnt_userns,
                       struct inode *old_dir, struct dentry *old_dentry,
                       struct inode *new_dir, struct dentry *new_dentry,
                       unsigned int flags)
{
    panic("%s: END!\n", __func__);
}

static struct dentry *
ext2_lookup(struct inode * dir, struct dentry *dentry, unsigned int flags)
{
    panic("%s: END!\n", __func__);
}

const struct inode_operations ext2_dir_inode_operations = {
    .create     = ext2_create,
    .lookup     = ext2_lookup,
    .link       = ext2_link,
    .unlink     = ext2_unlink,
    .symlink    = ext2_symlink,
    .mkdir      = ext2_mkdir,
    .rmdir      = ext2_rmdir,
    .mknod      = ext2_mknod,
    .rename     = ext2_rename,
    .listxattr  = NULL,
    .getattr    = ext2_getattr,
    .setattr    = ext2_setattr,
    .get_acl    = NULL,
    .set_acl    = NULL,
    .tmpfile    = ext2_tmpfile,
    .fileattr_get   = NULL,
    .fileattr_set   = NULL,
};
