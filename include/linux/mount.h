/* SPDX-License-Identifier: GPL-2.0 */
/*
 *
 * Definitions for mount interface. This describes the in the kernel build
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/nodemask.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/atomic.h>

struct super_block;
struct vfsmount;
struct dentry;
struct mnt_namespace;
struct fs_context;

struct vfsmount {
    struct dentry *mnt_root;    /* root of the mounted tree */
    struct super_block *mnt_sb; /* pointer to superblock */
    int mnt_flags;
#if 0
    struct user_namespace *mnt_userns;
#endif
} __randomize_layout;

extern struct vfsmount *vfs_create_mount(struct fs_context *fc);

#endif /* _LINUX_MOUNT_H */
