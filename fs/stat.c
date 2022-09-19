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
#include <linux/highuid.h>
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

#define choose_32_64(a,b) b

#ifndef INIT_STRUCT_STAT_PADDING
# define INIT_STRUCT_STAT_PADDING(st) memset(&st, 0, sizeof(st))
#endif

static int cp_new_stat(struct kstat *stat, struct stat __user *statbuf)
{
    struct stat tmp;

    if (sizeof(tmp.st_dev) < 4 && !old_valid_dev(stat->dev))
        return -EOVERFLOW;
    if (sizeof(tmp.st_rdev) < 4 && !old_valid_dev(stat->rdev))
        return -EOVERFLOW;

    INIT_STRUCT_STAT_PADDING(tmp);
    tmp.st_dev = new_encode_dev(stat->dev);
    tmp.st_ino = stat->ino;
    if (sizeof(tmp.st_ino) < sizeof(stat->ino) &&
        tmp.st_ino != stat->ino)
        return -EOVERFLOW;

    SET_UID(tmp.st_uid, from_kuid_munged(current_user_ns(), stat->uid));
    SET_GID(tmp.st_gid, from_kgid_munged(current_user_ns(), stat->gid));
    tmp.st_rdev = new_encode_dev(stat->rdev);
    tmp.st_size = stat->size;
#if 0
    tmp.st_atime = stat->atime.tv_sec;
    tmp.st_mtime = stat->mtime.tv_sec;
    tmp.st_ctime = stat->ctime.tv_sec;
    tmp.st_atime_nsec = stat->atime.tv_nsec;
    tmp.st_mtime_nsec = stat->mtime.tv_nsec;
    tmp.st_ctime_nsec = stat->ctime.tv_nsec;
#endif

    tmp.st_blocks = stat->blocks;
    tmp.st_blksize = stat->blksize;
    return copy_to_user(statbuf, &tmp, sizeof(tmp)) ? -EFAULT : 0;
}

SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
                struct stat __user *, statbuf, int, flag)
{
    struct kstat stat;
    int error;

    error = vfs_fstatat(dfd, filename, &stat, flag);
    if (error)
        return error;
    return cp_new_stat(&stat, statbuf);
}

/**
 * generic_fillattr - Fill in the basic attributes from the inode struct
 * @mnt_userns: user namespace of the mount the inode was found from
 * @inode:  Inode to use as the source
 * @stat:   Where to fill in the attributes
 *
 * Fill in the basic attributes in the kstat structure from data that's to be
 * found on the VFS inode structure.  This is the default if no getattr inode
 * operation is supplied.
 *
 * If the inode has been found through an idmapped mount the user namespace of
 * the vfsmount must be passed through @mnt_userns. This function will then
 * take care to map the inode according to @mnt_userns before filling in the
 * uid and gid filds. On non-idmapped mounts or if permission checking is to be
 * performed on the raw inode simply passs init_user_ns.
 */
void generic_fillattr(struct user_namespace *mnt_userns,
                      struct inode *inode,
                      struct kstat *stat)
{
    stat->dev = inode->i_sb->s_dev;
    stat->ino = inode->i_ino;
    stat->mode = inode->i_mode;
    stat->nlink = inode->i_nlink;
    stat->uid = i_uid_into_mnt(mnt_userns, inode);
    stat->gid = i_gid_into_mnt(mnt_userns, inode);
    stat->rdev = inode->i_rdev;
    stat->size = i_size_read(inode);
#if 0
    stat->atime = inode->i_atime;
    stat->mtime = inode->i_mtime;
    stat->ctime = inode->i_ctime;
#endif
    stat->blksize = i_blocksize(inode);
    stat->blocks = inode->i_blocks;
}
EXPORT_SYMBOL(generic_fillattr);

/**
 * vfs_getattr_nosec - getattr without security checks
 * @path: file to get attributes from
 * @stat: structure to return attributes in
 * @request_mask: STATX_xxx flags indicating what the caller wants
 * @query_flags: Query mode (AT_STATX_SYNC_TYPE)
 *
 * Get attributes without calling security_inode_getattr.
 *
 * Currently the only caller other than vfs_getattr is internal to the
 * filehandle lookup code, which uses only the inode number and returns no
 * attributes to any user.  Any other code probably wants vfs_getattr.
 */
int vfs_getattr_nosec(const struct path *path, struct kstat *stat,
                      u32 request_mask, unsigned int query_flags)
{
    struct user_namespace *mnt_userns;
    struct inode *inode = d_backing_inode(path->dentry);

    memset(stat, 0, sizeof(*stat));
    stat->result_mask |= STATX_BASIC_STATS;
    query_flags &= AT_STATX_SYNC_TYPE;

    /* allow the fs to override these if it really wants to */
    /* SB_NOATIME means filesystem supplies dummy atime value */
    if (inode->i_sb->s_flags & SB_NOATIME)
        stat->result_mask &= ~STATX_ATIME;

    /*
     * Note: If you add another clause to set an attribute flag, please
     * update attributes_mask below.
     */
    if (IS_AUTOMOUNT(inode))
        stat->attributes |= STATX_ATTR_AUTOMOUNT;

    if (IS_DAX(inode))
        stat->attributes |= STATX_ATTR_DAX;

    stat->attributes_mask |= (STATX_ATTR_AUTOMOUNT | STATX_ATTR_DAX);

    mnt_userns = mnt_user_ns(path->mnt);
    if (inode->i_op->getattr)
        return inode->i_op->getattr(mnt_userns, path, stat,
                                    request_mask, query_flags);

    generic_fillattr(mnt_userns, inode, stat);
    return 0;
}
EXPORT_SYMBOL(vfs_getattr_nosec);

/*
 * vfs_getattr - Get the enhanced basic attributes of a file
 * @path: The file of interest
 * @stat: Where to return the statistics
 * @request_mask: STATX_xxx flags indicating what the caller wants
 * @query_flags: Query mode (AT_STATX_SYNC_TYPE)
 *
 * Ask the filesystem for a file's attributes.  The caller must indicate in
 * request_mask and query_flags to indicate what they want.
 *
 * If the file is remote, the filesystem can be forced to update the attributes
 * from the backing store by passing AT_STATX_FORCE_SYNC in query_flags or can
 * suppress the update by passing AT_STATX_DONT_SYNC.
 *
 * Bits must have been set in request_mask to indicate which attributes the
 * caller wants retrieving.  Any such attribute not requested may be returned
 * anyway, but the value may be approximate, and, if remote, may not have been
 * synchronised with the server.
 *
 * 0 will be returned on success, and a -ve error code if unsuccessful.
 */
int vfs_getattr(const struct path *path, struct kstat *stat,
                u32 request_mask, unsigned int query_flags)
{
    int retval;

    return vfs_getattr_nosec(path, stat, request_mask, query_flags);
}
EXPORT_SYMBOL(vfs_getattr);

/**
 * vfs_fstat - Get the basic attributes by file descriptor
 * @fd: The file descriptor referring to the file of interest
 * @stat: The result structure to fill in.
 *
 * This function is a wrapper around vfs_getattr().  The main difference is
 * that it uses a file descriptor to determine the file location.
 *
 * 0 will be returned on success, and a -ve error code if unsuccessful.
 */
int vfs_fstat(int fd, struct kstat *stat)
{
    struct fd f;
    int error;

    f = fdget_raw(fd);
    if (!f.file)
        return -EBADF;
    error = vfs_getattr(&f.file->f_path, stat, STATX_BASIC_STATS, 0);
    fdput(f);
    return error;
}

SYSCALL_DEFINE2(newfstat, unsigned int, fd,
                struct stat __user *, statbuf)
{
    struct kstat stat;
    int error = vfs_fstat(fd, &stat);

    if (!error)
        error = cp_new_stat(&stat, statbuf);

    return error;
}

SYSCALL_DEFINE2(newstat, const char __user *, filename,
                struct stat __user *, statbuf)
{
    struct kstat stat;
    int error = vfs_stat(filename, &stat);

    if (error)
        return error;
    return cp_new_stat(&stat, statbuf);
}
