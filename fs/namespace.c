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
#include <linux/namei.h>
#endif
#include <linux/cred.h>
#include <linux/user_namespace.h>
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
#endif
#include <linux/shmem_fs.h>
#include <linux/mnt_idmapping.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/kobject.h>
#include <linux/path.h>

#if 0
#include "pnode.h"
#endif
#include "mount.h"
#include "internal.h"

static struct hlist_head *mount_hashtable __read_mostly;
static struct hlist_head *mountpoint_hashtable __read_mostly;
static struct kmem_cache *mnt_cache __read_mostly;

static __initdata unsigned long mhash_entries;
static __initdata unsigned long mphash_entries;

static unsigned int m_hash_mask __read_mostly;
static unsigned int m_hash_shift __read_mostly;
static unsigned int mp_hash_mask __read_mostly;
static unsigned int mp_hash_shift __read_mostly;

/* /sys/fs */
struct kobject *fs_kobj;
EXPORT_SYMBOL_GPL(fs_kobj);

static DEFINE_IDA(mnt_id_ida);
static DEFINE_IDA(mnt_group_ida);

/*
 * vfsmount lock may be taken for read to prevent changes to the
 * vfsmount hash, ie. during mountpoint lookups or walking back
 * up the tree.
 *
 * It should be taken for write in all cases where the vfsmount
 * tree or hash is modified or when a vfsmount structure is modified.
 */
__cacheline_aligned_in_smp DEFINE_SEQLOCK(mount_lock);

static inline void lock_mount_hash(void)
{
    write_seqlock(&mount_lock);
}

static inline void unlock_mount_hash(void)
{
    write_sequnlock(&mount_lock);
}

static int mnt_alloc_id(struct mount *mnt)
{
    int res = ida_alloc(&mnt_id_ida, GFP_KERNEL);

    if (res < 0)
        return res;
    mnt->mnt_id = res;
    return 0;
}

static void mnt_free_id(struct mount *mnt)
{
    ida_free(&mnt_id_ida, mnt->mnt_id);
}

static struct mount *alloc_vfsmnt(const char *name)
{
    struct mount *mnt = kmem_cache_zalloc(mnt_cache, GFP_KERNEL);
    if (mnt) {
        int err;

        err = mnt_alloc_id(mnt);
        if (err)
            goto out_free_cache;

        if (name) {
            mnt->mnt_devname = kstrdup_const(name, GFP_KERNEL_ACCOUNT);
            if (!mnt->mnt_devname)
                goto out_free_id;
        }

        mnt->mnt_pcp = alloc_percpu(struct mnt_pcp);
        if (!mnt->mnt_pcp)
            goto out_free_devname;

        this_cpu_add(mnt->mnt_pcp->mnt_count, 1);

        INIT_HLIST_NODE(&mnt->mnt_hash);
        INIT_LIST_HEAD(&mnt->mnt_child);
        INIT_LIST_HEAD(&mnt->mnt_mounts);
        INIT_LIST_HEAD(&mnt->mnt_list);
        INIT_LIST_HEAD(&mnt->mnt_expire);
        INIT_LIST_HEAD(&mnt->mnt_share);
        INIT_LIST_HEAD(&mnt->mnt_slave_list);
        INIT_LIST_HEAD(&mnt->mnt_slave);
        INIT_HLIST_NODE(&mnt->mnt_mp_list);
        INIT_LIST_HEAD(&mnt->mnt_umounting);
        INIT_HLIST_HEAD(&mnt->mnt_stuck_children);
        mnt->mnt.mnt_userns = &init_user_ns;
    }
    return mnt;

 out_free_devname:
    kfree_const(mnt->mnt_devname);

 out_free_id:
    mnt_free_id(mnt);

 out_free_cache:
    kmem_cache_free(mnt_cache, mnt);
    return NULL;
}

/**
 * vfs_create_mount - Create a mount for a configured superblock
 * @fc: The configuration context with the superblock attached
 *
 * Create a mount to an already configured superblock.  If necessary, the
 * caller should invoke vfs_get_tree() before calling this.
 *
 * Note that this does not attach the mount to anything.
 */
struct vfsmount *vfs_create_mount(struct fs_context *fc)
{
    struct mount *mnt;
    struct user_namespace *fs_userns;

    if (!fc->root)
        return ERR_PTR(-EINVAL);

    mnt = alloc_vfsmnt(fc->source ?: "none");
    if (!mnt)
        return ERR_PTR(-ENOMEM);

    if (fc->sb_flags & SB_KERNMOUNT)
        mnt->mnt.mnt_flags = MNT_INTERNAL;

    atomic_inc(&fc->root->d_sb->s_active);
    mnt->mnt.mnt_sb     = fc->root->d_sb;
    mnt->mnt.mnt_root   = dget(fc->root);
    mnt->mnt_mountpoint = mnt->mnt.mnt_root;
    mnt->mnt_parent     = mnt;

    fs_userns = mnt->mnt.mnt_sb->s_user_ns;
    if (!initial_idmapping(fs_userns))
        mnt->mnt.mnt_userns = get_user_ns(fs_userns);

    lock_mount_hash();
    list_add_tail(&mnt->mnt_instance, &mnt->mnt.mnt_sb->s_mounts);
    unlock_mount_hash();
    return &mnt->mnt;
}
EXPORT_SYMBOL(vfs_create_mount);

struct vfsmount *fc_mount(struct fs_context *fc)
{
    int err = vfs_get_tree(fc);
    if (!err) {
        up_write(&fc->root->d_sb->s_umount);
        return vfs_create_mount(fc);
    }
    return ERR_PTR(err);
}
EXPORT_SYMBOL(fc_mount);

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

    if (name)
        ret = vfs_parse_fs_string(fc, "source", name, strlen(name));
    if (!ret)
        ret = parse_monolithic_mount_data(fc, data);
    if (!ret)
        mnt = fc_mount(fc);
    else
        mnt = ERR_PTR(ret);

    put_fs_context(fc);
    return mnt;
}
EXPORT_SYMBOL_GPL(vfs_kern_mount);

struct vfsmount *kern_mount(struct file_system_type *type)
{
    struct vfsmount *mnt;
    mnt = vfs_kern_mount(type, SB_KERNMOUNT, type->name, NULL);
    if (!IS_ERR(mnt)) {
        /*
         * it is a longterm mount, don't release mnt until
         * we unmount before file sys is unregistered
        */
        real_mount(mnt)->mnt_ns = MNT_NS_INTERNAL;
    }
    return mnt;
}
EXPORT_SYMBOL_GPL(kern_mount);

static void __init init_mount_tree(void)
{
    struct vfsmount *mnt;
    struct mount *m;
    struct mnt_namespace *ns;
    struct path root;

    mnt = vfs_kern_mount(&rootfs_fs_type, 0, "rootfs", NULL);
    if (IS_ERR(mnt))
        panic("Can't create rootfs");

#if 0
    ns = alloc_mnt_ns(&init_user_ns, false);
    if (IS_ERR(ns))
        panic("Can't allocate initial namespace");
    m = real_mount(mnt);
    m->mnt_ns = ns;
    ns->root = m;
    ns->mounts = 1;
    list_add(&m->mnt_list, &ns->list);
    init_task.nsproxy->mnt_ns = ns;
    get_mnt_ns(ns);

    root.mnt = mnt;
    root.dentry = mnt->mnt_root;
    mnt->mnt_flags |= MNT_LOCKED;

    set_fs_pwd(current->fs, &root);
    set_fs_root(current->fs, &root);
#endif
    panic("%s: END!\n", __func__);
}

void __init mnt_init(void)
{
    int err;

    mnt_cache =
        kmem_cache_create("mnt_cache", sizeof(struct mount),
                          0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);

    mount_hashtable =
        alloc_large_system_hash("Mount-cache",
                                sizeof(struct hlist_head),
                                mhash_entries, 19, HASH_ZERO,
                                &m_hash_shift, &m_hash_mask, 0, 0);
    mountpoint_hashtable =
        alloc_large_system_hash("Mountpoint-cache",
                                sizeof(struct hlist_head),
                                mphash_entries, 19, HASH_ZERO,
                                &mp_hash_shift, &mp_hash_mask, 0, 0);

    if (!mount_hashtable || !mountpoint_hashtable)
        panic("Failed to allocate mount hash table\n");

#if 0
    kernfs_init();

    err = sysfs_init();
    if (err)
        printk(KERN_WARNING "%s: sysfs_init error: %d\n",
            __func__, err);
#endif
    fs_kobj = kobject_create_and_add("fs", NULL);
    if (!fs_kobj)
        printk(KERN_WARNING "%s: kobj create error\n", __func__);
    shmem_init();
    init_rootfs();
    init_mount_tree();
}
