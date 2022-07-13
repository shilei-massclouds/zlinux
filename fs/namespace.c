// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/namespace.c
 *
 * (C) Copyright Al Viro 2000, 2001
 *
 * Based on code from fs/super.c, copyright Linus Torvalds and others.
 * Heavily rewritten.
 */

#if 0
#include <linux/syscalls.h>
#endif
#include <linux/export.h>
#if 0
#include <linux/capability.h>
#include <linux/mnt_namespace.h>
#include <linux/user_namespace.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/cred.h>
#endif
#include <linux/idr.h>
#include <linux/init.h>         /* init_rootfs */
#if 0
#include <linux/fs_struct.h>    /* get_fs_root et.al. */
#include <linux/fsnotify.h>     /* fsnotify_vfsmount_delete */
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/proc_ns.h>
#endif
#include <linux/magic.h>
#include <linux/memblock.h>
#if 0
#include <linux/proc_fs.h>
#include <linux/task_work.h>
#endif
#include <linux/sched/task.h>
#if 0
#include <uapi/linux/mount.h>
#include <linux/shmem_fs.h>
#include <linux/mnt_idmapping.h>
#endif
#include <linux/fs.h>
#include <linux/fs_context.h>

struct vfsmount *
vfs_kern_mount(struct file_system_type *type, int flags, const char *name,
               void *data)
{
    struct fs_context *fc;
    struct vfsmount *mnt;
    int ret = 0;

    if (!type)
        return ERR_PTR(-EINVAL);

    fc = fs_context_for_mount(type, flags);
    if (IS_ERR(fc))
        return ERR_CAST(fc);

#if 0
    if (name)
        ret = vfs_parse_fs_string(fc, "source", name, strlen(name));
    if (!ret)
        ret = parse_monolithic_mount_data(fc, data);
    if (!ret)
        mnt = fc_mount(fc);
    else
        mnt = ERR_PTR(ret);

    put_fs_context(fc);
#endif
    panic("%s: END!\n", __func__);
    return mnt;
}
EXPORT_SYMBOL_GPL(vfs_kern_mount);

struct vfsmount *kern_mount(struct file_system_type *type)
{
    struct vfsmount *mnt;
    mnt = vfs_kern_mount(type, SB_KERNMOUNT, type->name, NULL);
#if 0
    if (!IS_ERR(mnt)) {
        /*
         * it is a longterm mount, don't release mnt until
         * we unmount before file sys is unregistered
        */
        real_mount(mnt)->mnt_ns = MNT_NS_INTERNAL;
    }
#endif
    panic("%s: END!\n", __func__);
    return mnt;
}
EXPORT_SYMBOL_GPL(kern_mount);
