// SPDX-License-Identifier: GPL-2.0
/*
 * Routines that mimic syscalls, but don't use the user address space or file
 * descriptors.  Only for init/ and related early init code.
 */
#include <linux/init.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
//#include <linux/file.h>
#include <linux/init_syscalls.h>
#include "internal.h"

int __init init_mkdir(const char *pathname, umode_t mode)
{
    struct dentry *dentry;
    struct path path;
    int error;

    dentry = kern_path_create(AT_FDCWD, pathname, &path, LOOKUP_DIRECTORY);
    if (IS_ERR(dentry))
        return PTR_ERR(dentry);
    if (!IS_POSIXACL(path.dentry->d_inode))
        mode &= ~current_umask();
    error = vfs_mkdir(mnt_user_ns(path.mnt), path.dentry->d_inode,
                      dentry, mode);
    done_path_create(&path, dentry);
    return error;
}

int __init init_mknod(const char *filename, umode_t mode, unsigned int dev)
{
    struct dentry *dentry;
    struct path path;
    int error;

    if (S_ISFIFO(mode) || S_ISSOCK(mode))
        dev = 0;
    else if (!(S_ISBLK(mode) || S_ISCHR(mode)))
        return -EINVAL;

    dentry = kern_path_create(AT_FDCWD, filename, &path, 0);
    if (IS_ERR(dentry))
        return PTR_ERR(dentry);

    if (!IS_POSIXACL(path.dentry->d_inode))
        mode &= ~current_umask();
    error = vfs_mknod(mnt_user_ns(path.mnt), path.dentry->d_inode,
                      dentry, mode, new_decode_dev(dev));
    done_path_create(&path, dentry);
    return error;
}

int __init init_eaccess(const char *filename)
{
    struct path path;
    int error;

    error = kern_path(filename, LOOKUP_FOLLOW, &path);
    if (error)
        return error;
    error = path_permission(&path, MAY_ACCESS);
    path_put(&path);
    return error;
}

int __init init_unlink(const char *pathname)
{
    return do_unlinkat(AT_FDCWD, getname_kernel(pathname));
}

int __init init_mount(const char *dev_name, const char *dir_name,
                      const char *type_page, unsigned long flags,
                      void *data_page)
{
    struct path path;
    int ret;

    ret = kern_path(dir_name, LOOKUP_FOLLOW, &path);
    if (ret)
        return ret;
    ret = path_mount(dev_name, &path, type_page, flags, data_page);
    path_put(&path);
    return ret;
}

int __init init_chdir(const char *filename)
{
    struct path path;
    int error;

    error = kern_path(filename, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
    if (error)
        return error;
    error = path_permission(&path, MAY_EXEC | MAY_CHDIR);
    if (!error)
        set_fs_pwd(current->fs, &path);
    path_put(&path);
    return error;
}

int __init init_chroot(const char *filename)
{
    struct path path;
    int error;

    error = kern_path(filename, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
    if (error)
        return error;
#if 0
    error = path_permission(&path, MAY_EXEC | MAY_CHDIR);
    if (error)
        goto dput_and_out;
    error = -EPERM;
    if (!ns_capable(current_user_ns(), CAP_SYS_CHROOT))
        goto dput_and_out;
#endif
    set_fs_root(current->fs, &path);
 dput_and_out:
    path_put(&path);
    return error;
}
