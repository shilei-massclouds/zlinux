// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/stat.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/file.h>
//#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/compat.h>

#include <linux/uaccess.h>
#include <asm/unistd.h>

#include "internal.h"
#include "mount.h"

static int do_readlinkat(int dfd, const char __user *pathname,
                         char __user *buf, int bufsiz)
{
    struct path path;
    int error;
    int empty = 0;
    unsigned int lookup_flags = LOOKUP_EMPTY;

    printk("%s: ...\n", __func__);

    if (bufsiz <= 0)
        return -EINVAL;

 retry:
    error = user_path_at_empty(dfd, pathname, lookup_flags, &path, &empty);
    if (!error) {
        panic("%s: !error!\n", __func__);
    }
    printk("%s: error(%d)\n", __func__, error);
    return error;
}

SYSCALL_DEFINE4(readlinkat, int, dfd, const char __user *, pathname,
                char __user *, buf, int, bufsiz)
{
    return do_readlinkat(dfd, pathname, buf, bufsiz);
}

int getname_statx_lookup_flags(int flags)
{
    int lookup_flags = 0;

    if (!(flags & AT_SYMLINK_NOFOLLOW))
        lookup_flags |= LOOKUP_FOLLOW;
    if (!(flags & AT_NO_AUTOMOUNT))
        lookup_flags |= LOOKUP_AUTOMOUNT;
    if (flags & AT_EMPTY_PATH)
        lookup_flags |= LOOKUP_EMPTY;

    return lookup_flags;
}

/**
 * vfs_statx - Get basic and extra attributes by filename
 * @dfd: A file descriptor representing the base dir for a relative filename
 * @filename: The name of the file of interest
 * @flags: Flags to control the query
 * @stat: The result structure to fill in.
 * @request_mask: STATX_xxx flags indicating what the caller wants
 *
 * This function is a wrapper around vfs_getattr().  The main difference is
 * that it uses a filename and base directory to determine the file location.
 * Additionally, the use of AT_SYMLINK_NOFOLLOW in flags will prevent a symlink
 * at the given name from being referenced.
 *
 * 0 will be returned on success, and a -ve error code if unsuccessful.
 */
static int vfs_statx(int dfd, struct filename *filename, int flags,
                     struct kstat *stat, u32 request_mask)
{
    struct path path;
    unsigned int lookup_flags = getname_statx_lookup_flags(flags);
    int error;

    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
                  AT_EMPTY_PATH | AT_STATX_SYNC_TYPE))
        return -EINVAL;

 retry:
    error = filename_lookup(dfd, filename, lookup_flags, &path, NULL);
    if (error)
        goto out;

    panic("%s: END!\n", __func__);

 out:
    return error;
}

int vfs_fstatat(int dfd, const char __user *filename,
                struct kstat *stat, int flags)
{
    int ret;
    int statx_flags = flags | AT_NO_AUTOMOUNT;
    struct filename *name;

    name = getname_flags(filename,
                         getname_statx_lookup_flags(statx_flags), NULL);
    ret = vfs_statx(dfd, name, statx_flags, stat, STATX_BASIC_STATS);
    putname(name);

    return ret;
}

SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
                struct stat __user *, statbuf, int, flag)
{
    struct kstat stat;
    int error;

    error = vfs_fstatat(dfd, filename, &stat, flag);
    if (error)
        return error;
#if 0
    return cp_new_stat(&stat, statbuf);
#endif
    panic("%s: END!\n", __func__);
}
