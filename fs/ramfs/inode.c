/*
 * Resizable simple ram filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 */

/*
 * NOTE! This filesystem is probably most useful
 * not as a real filesystem, but as an example of
 * how virtual filesystems can be written.
 *
 * It doesn't get much simpler than this. Consider
 * that this file implements the full semantics of
 * a POSIX-compliant read-write filesystem.
 *
 * Note in particular how the filesystem does not
 * need to implement any data structures of its own
 * to keep track of the virtual data: using the VFS
 * caches is sufficient.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#if 0
#include <linux/time.h>
#endif
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/ramfs.h>
#include <linux/sched.h>
#if 0
#include <linux/parser.h>
#endif
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#if 0
#include <linux/seq_file.h>
#include "internal.h"
#endif

struct ramfs_mount_opts {
    umode_t mode;
};

struct ramfs_fs_info {
    struct ramfs_mount_opts mount_opts;
};

struct inode *ramfs_get_inode(struct super_block *sb,
                              const struct inode *dir, umode_t mode, dev_t dev);

/*
 * Display the mount options in /proc/mounts.
 */
static int ramfs_show_options(struct seq_file *m, struct dentry *root)
{
    struct ramfs_fs_info *fsi = root->d_sb->s_fs_info;

#if 0
    if (fsi->mount_opts.mode != RAMFS_DEFAULT_MODE)
        seq_printf(m, ",mode=%o", fsi->mount_opts.mode);
#endif
    panic("%s: END!\n", __func__);
    return 0;
}

static const struct super_operations ramfs_ops = {
    .statfs         = simple_statfs,
    .drop_inode     = generic_delete_inode,
    .show_options   = ramfs_show_options,
};

enum ramfs_param {
    Opt_mode,
};

#define RAMFS_DEFAULT_MODE  0755

/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
static int
ramfs_mknod(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode, dev_t dev)
{
    struct inode *inode = ramfs_get_inode(dir->i_sb, dir, mode, dev);
    int error = -ENOSPC;

    if (inode) {
        d_instantiate(dentry, inode);
        dget(dentry);   /* Extra count - pin the dentry in core */
        error = 0;
        dir->i_mtime = dir->i_ctime = current_time(dir);
    }
    return error;
}

static int ramfs_create(struct user_namespace *mnt_userns, struct inode *dir,
                        struct dentry *dentry, umode_t mode, bool excl)
{
    return ramfs_mknod(&init_user_ns, dir, dentry, mode | S_IFREG, 0);
}

static int ramfs_symlink(struct user_namespace *mnt_userns, struct inode *dir,
                         struct dentry *dentry, const char *symname)
{
    panic("%s: END!\n", __func__);
}

static int ramfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
                       struct dentry *dentry, umode_t mode)
{
    int retval = ramfs_mknod(&init_user_ns, dir, dentry, mode | S_IFDIR, 0);
    if (!retval)
        inc_nlink(dir);
    return retval;
}

static int ramfs_tmpfile(struct user_namespace *mnt_userns,
             struct inode *dir, struct dentry *dentry, umode_t mode)
{
    struct inode *inode;

    inode = ramfs_get_inode(dir->i_sb, dir, mode, 0);
    if (!inode)
        return -ENOSPC;
    d_tmpfile(dentry, inode);
    return 0;
}

static const struct inode_operations ramfs_dir_inode_operations = {
    .create     = ramfs_create,
    .lookup     = simple_lookup,
    .link       = simple_link,
    .unlink     = simple_unlink,
    .symlink    = ramfs_symlink,
    .mkdir      = ramfs_mkdir,
    .rmdir      = simple_rmdir,
    .mknod      = ramfs_mknod,
    .rename     = simple_rename,
    .tmpfile    = ramfs_tmpfile,
};

struct inode *ramfs_get_inode(struct super_block *sb,
                              const struct inode *dir, umode_t mode, dev_t dev)
{
    struct inode *inode = new_inode(sb);

    if (inode) {
        inode->i_ino = get_next_ino();
        inode_init_owner(&init_user_ns, inode, dir, mode);
        inode->i_mapping->a_ops = &ram_aops;
        mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
        mapping_set_unevictable(inode->i_mapping);
        inode->i_atime = inode->i_mtime = inode->i_ctime =
            current_time(inode);

        switch (mode & S_IFMT) {
        default:
            init_special_inode(inode, mode, dev);
            break;
        case S_IFREG:
#if 0
            inode->i_op = &ramfs_file_inode_operations;
            inode->i_fop = &ramfs_file_operations;
#endif
            panic("%s: S_IFREG!\n", __func__);
            break;
        case S_IFDIR:
            inode->i_op = &ramfs_dir_inode_operations;
            inode->i_fop = &simple_dir_operations;

            /* directory inodes start off with i_nlink == 2 (for "." entry) */
            inc_nlink(inode);
            break;
        case S_IFLNK:
#if 0
            inode->i_op = &page_symlink_inode_operations;
            inode_nohighmem(inode);
#endif
            panic("%s: S_IFLNK!\n", __func__);
            break;
        }
    }
    return inode;
}

static void ramfs_free_fc(struct fs_context *fc)
{
    kfree(fc->s_fs_info);
}

const struct fs_parameter_spec ramfs_fs_parameters[] = {
    fsparam_u32oct("mode",  Opt_mode),
    {}
};

static int ramfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct fs_parse_result result;
    struct ramfs_fs_info *fsi = fc->s_fs_info;
    int opt;

    opt = fs_parse(fc, ramfs_fs_parameters, param, &result);
    if (opt == -ENOPARAM) {
        opt = vfs_parse_fs_param_source(fc, param);
        if (opt != -ENOPARAM)
            return opt;
        /*
         * We might like to report bad mount options here;
         * but traditionally ramfs has ignored all mount options,
         * and as it is used as a !CONFIG_SHMEM simple substitute
         * for tmpfs, better continue to ignore other mount options.
         */
        return 0;
    }
    if (opt < 0)
        return opt;

    switch (opt) {
    case Opt_mode:
        fsi->mount_opts.mode = result.uint_32 & S_IALLUGO;
        break;
    }

    return 0;
}

static int ramfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct ramfs_fs_info *fsi = sb->s_fs_info;
    struct inode *inode;

    sb->s_maxbytes      = MAX_LFS_FILESIZE;
    sb->s_blocksize     = PAGE_SIZE;
    sb->s_blocksize_bits    = PAGE_SHIFT;
    sb->s_magic     = RAMFS_MAGIC;
    sb->s_op        = &ramfs_ops;
    sb->s_time_gran     = 1;

    inode = ramfs_get_inode(sb, NULL, S_IFDIR | fsi->mount_opts.mode, 0);
    sb->s_root = d_make_root(inode);
    if (!sb->s_root)
        return -ENOMEM;

    return 0;
}

static int ramfs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, ramfs_fill_super);
}

static const struct fs_context_operations ramfs_context_ops = {
    .free           = ramfs_free_fc,
    .parse_param    = ramfs_parse_param,
    .get_tree       = ramfs_get_tree,
};

int ramfs_init_fs_context(struct fs_context *fc)
{
    struct ramfs_fs_info *fsi;

    fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
    if (!fsi)
        return -ENOMEM;

    fsi->mount_opts.mode = RAMFS_DEFAULT_MODE;
    fc->s_fs_info = fsi;
    fc->ops = &ramfs_context_ops;
    return 0;
}
