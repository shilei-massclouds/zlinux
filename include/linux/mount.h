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

#define MNT_INTERNAL        0x4000

#define MNT_LOCK_ATIME      0x040000
#define MNT_LOCK_NOEXEC     0x080000
#define MNT_LOCK_NOSUID     0x100000
#define MNT_LOCK_NODEV      0x200000
#define MNT_LOCK_READONLY   0x400000
#define MNT_LOCKED          0x800000
#define MNT_DOOMED          0x1000000
#define MNT_SYNC_UMOUNT     0x2000000
#define MNT_MARKED          0x4000000
#define MNT_UMOUNT          0x8000000
#define MNT_CURSOR          0x10000000

struct vfsmount {
    struct dentry *mnt_root;    /* root of the mounted tree */
    struct super_block *mnt_sb; /* pointer to superblock */
    int mnt_flags;
    struct user_namespace *mnt_userns;
} __randomize_layout;

extern struct vfsmount *vfs_create_mount(struct fs_context *fc);

extern struct vfsmount *mntget(struct vfsmount *mnt);
extern void mntput(struct vfsmount *mnt);

extern void mnt_drop_write(struct vfsmount *mnt);

static inline struct user_namespace *mnt_user_ns(const struct vfsmount *mnt)
{
    /* Pairs with smp_store_release() in do_idmap_mount(). */
    return smp_load_acquire(&mnt->mnt_userns);
}

#endif /* _LINUX_MOUNT_H */
