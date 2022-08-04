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
#include <linux/fs_struct.h>    /* get_fs_root et.al. */
#if 0
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
#include <uapi/linux/mount.h>
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

static struct ucounts *inc_mnt_namespaces(struct user_namespace *ns)
{
#if 0
    return inc_ucount(ns, current_euid(), UCOUNT_MNT_NAMESPACES);
#endif
    panic("%s: END!\n", __func__);
}

static void dec_mnt_namespaces(struct ucounts *ucounts)
{
#if 0
    dec_ucount(ucounts, UCOUNT_MNT_NAMESPACES);
#endif
    panic("%s: END!\n", __func__);
}


static struct mnt_namespace *
alloc_mnt_ns(struct user_namespace *user_ns, bool anon)
{
    struct mnt_namespace *new_ns;
    struct ucounts *ucounts;
    int ret;

#if 0
    ucounts = inc_mnt_namespaces(user_ns);
    if (!ucounts)
        return ERR_PTR(-ENOSPC);
#endif

    new_ns = kzalloc(sizeof(struct mnt_namespace), GFP_KERNEL_ACCOUNT);
    if (!new_ns) {
#if 0
        dec_mnt_namespaces(ucounts);
#endif
        return ERR_PTR(-ENOMEM);
    }
    if (!anon) {
        pr_warn("%s: NOT anon!\n", __func__);
#if 0
        ret = ns_alloc_inum(&new_ns->ns);
        if (ret) {
            kfree(new_ns);
            dec_mnt_namespaces(ucounts);
            return ERR_PTR(ret);
        }
#endif
    }

#if 0
    new_ns->ns.ops = &mntns_operations;
    if (!anon)
        new_ns->seq = atomic64_add_return(1, &mnt_ns_seq);
#endif
    refcount_set(&new_ns->ns.count, 1);
    INIT_LIST_HEAD(&new_ns->list);
    //init_waitqueue_head(&new_ns->poll);
    spin_lock_init(&new_ns->ns_lock);
    new_ns->user_ns = get_user_ns(user_ns);
    //new_ns->ucounts = ucounts;
    return new_ns;
}

/*
 * vfsmount lock must be held for read
 */
static inline void mnt_add_count(struct mount *mnt, int n)
{
    this_cpu_add(mnt->mnt_pcp->mnt_count, n);
}

struct vfsmount *mntget(struct vfsmount *mnt)
{
    if (mnt)
        mnt_add_count(real_mount(mnt), 1);
    return mnt;
}
EXPORT_SYMBOL(mntget);

void mntput(struct vfsmount *mnt)
{
#if 0
    if (mnt) {
        struct mount *m = real_mount(mnt);
        /* avoid cacheline pingpong, hope gcc doesn't get "smart" */
        if (unlikely(m->mnt_expiry_mark))
            m->mnt_expiry_mark = 0;
        mntput_no_expire(m);
    }
#endif
    pr_warn("%s: END!\n", __func__);
}
EXPORT_SYMBOL(mntput);

/*
 * Return true if path is reachable from root
 *
 * namespace_sem or mount_lock is held
 */
bool is_path_reachable(struct mount *mnt, struct dentry *dentry,
                       const struct path *root)
{
    while (&mnt->mnt != root->mnt && mnt_has_parent(mnt)) {
        dentry = mnt->mnt_mountpoint;
        mnt = mnt->mnt_parent;
    }
#if 0
    return &mnt->mnt == root->mnt && is_subdir(dentry, root->dentry);
#endif
    panic("%s: END!\n", __func__);
}

bool path_is_under(const struct path *path1, const struct path *path2)
{
    bool res;
    //read_seqlock_excl(&mount_lock);
    res = is_path_reachable(real_mount(path1->mnt), path1->dentry, path2);
    //read_sequnlock_excl(&mount_lock);
    return res;
}
EXPORT_SYMBOL(path_is_under);

static void __init init_mount_tree(void)
{
    struct vfsmount *mnt;
    struct mount *m;
    struct mnt_namespace *ns;
    struct path root;

    mnt = vfs_kern_mount(&rootfs_fs_type, 0, "rootfs", NULL);
    if (IS_ERR(mnt))
        panic("Can't create rootfs");

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
}

static inline void mnt_dec_writers(struct mount *mnt)
{
    this_cpu_dec(mnt->mnt_pcp->mnt_writers);
}

/**
 * __mnt_drop_write - give up write access to a mount
 * @mnt: the mount on which to give up write access
 *
 * Tells the low-level filesystem that we are done
 * performing writes to it.  Must be matched with
 * __mnt_want_write() call above.
 */
void __mnt_drop_write(struct vfsmount *mnt)
{
    preempt_disable();
    mnt_dec_writers(real_mount(mnt));
    preempt_enable();
}

/**
 * mnt_drop_write - give up write access to a mount
 * @mnt: the mount on which to give up write access
 *
 * Tells the low-level filesystem that we are done performing writes to it and
 * also allows filesystem to be frozen again.  Must be matched with
 * mnt_want_write() call above.
 */
void mnt_drop_write(struct vfsmount *mnt)
{
#if 0
    __mnt_drop_write(mnt);
    sb_end_write(mnt->mnt_sb);
#endif
    pr_warn("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(mnt_drop_write);

static void warn_mandlock(void)
{
    pr_warn_once("=======================================================\n"
                 "WARNING: The mand mount option has been deprecated and\n"
                 "         and is ignored by this kernel. Remove the mand\n"
                 "         option from the mount to silence this warning.\n"
                 "=======================================================\n");
}

/*
 * Handle reconfiguration of the mountpoint only without alteration of the
 * superblock it refers to.  This is triggered by specifying MS_REMOUNT|MS_BIND
 * to mount(2).
 */
static int do_reconfigure_mnt(struct path *path, unsigned int mnt_flags)
{
    panic("%s: END!\n", __func__);
}

/*
 * change filesystem flags. dir should be a physical root of filesystem.
 * If you've mounted a non-root directory somewhere and want to do remount
 * on it - tough luck.
 */
static int do_remount(struct path *path, int ms_flags, int sb_flags,
                      int mnt_flags, void *data)
{
    panic("%s: END!\n", __func__);
}

/*
 * do loopback mount.
 */
static int do_loopback(struct path *path, const char *old_name, int recurse)
{
    panic("%s: END!\n", __func__);
}

/*
 * recursively change the type of the mountpoint.
 */
static int do_change_type(struct path *path, int ms_flags)
{
    panic("%s: END!\n", __func__);
}

static int do_move_mount_old(struct path *path, const char *old_name)
{
    panic("%s: END!\n", __func__);
}

/*
 * Create a new mount using a superblock configuration and request it
 * be added to the namespace tree.
 */
static int do_new_mount_fc(struct fs_context *fc, struct path *mountpoint,
                           unsigned int mnt_flags)
{
    panic("%s: END!\n", __func__);
}

/*
 * create a new mount for userspace and request it to be added into the
 * namespace's tree
 */
static int do_new_mount(struct path *path, const char *fstype, int sb_flags,
                        int mnt_flags, const char *name, void *data)
{
    struct file_system_type *type;
    struct fs_context *fc;
    const char *subtype = NULL;
    int err = 0;

    if (!fstype)
        return -EINVAL;

    type = get_fs_type(fstype);
    if (!type)
        return -ENODEV;

    if (type->fs_flags & FS_HAS_SUBTYPE) {
        subtype = strchr(fstype, '.');
        if (subtype) {
            subtype++;
            if (!*subtype) {
                put_filesystem(type);
                return -EINVAL;
            }
        }
    }

    fc = fs_context_for_mount(type, sb_flags);
    put_filesystem(type);
    if (IS_ERR(fc))
        return PTR_ERR(fc);

    if (subtype)
        err = vfs_parse_fs_string(fc, "subtype", subtype, strlen(subtype));
    if (!err && name)
        err = vfs_parse_fs_string(fc, "source", name, strlen(name));
    if (!err)
        err = parse_monolithic_mount_data(fc, data);
#if 0
    if (!err && !mount_capable(fc))
        err = -EPERM;
#endif
    if (!err)
        err = vfs_get_tree(fc);
    if (!err)
        err = do_new_mount_fc(fc, path, mnt_flags);

    put_fs_context(fc);
    return err;
}

/*
 * Flags is a 32-bit value that allows up to 31 non-fs dependent flags to
 * be given to the mount() call (ie: read-only, no-dev, no-suid etc).
 *
 * data is a (void *) that can point to any structure up to
 * PAGE_SIZE-1 bytes, which can contain arbitrary fs-dependent
 * information (or be NULL).
 *
 * Pre-0.97 versions of mount() didn't have a flags word.
 * When the flags word was introduced its top half was required
 * to have the magic value 0xC0ED, and this remained so until 2.4.0-test9.
 * Therefore, if this magic number is present, it carries no information
 * and must be discarded.
 */
int path_mount(const char *dev_name, struct path *path,
               const char *type_page, unsigned long flags, void *data_page)
{
    unsigned int mnt_flags = 0, sb_flags;
    int ret;

    /* Discard magic */
    if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
        flags &= ~MS_MGC_MSK;

    /* Basic sanity checks */
    if (data_page)
        ((char *)data_page)[PAGE_SIZE - 1] = 0;

    if (flags & MS_NOUSER)
        return -EINVAL;

#if 0
    if (!may_mount())
        return -EPERM;
#endif
    if (flags & SB_MANDLOCK)
        warn_mandlock();

    /* Default to relatime unless overriden */
    if (!(flags & MS_NOATIME))
        mnt_flags |= MNT_RELATIME;

    /* Separate the per-mountpoint flags */
    if (flags & MS_NOSUID)
        mnt_flags |= MNT_NOSUID;
    if (flags & MS_NODEV)
        mnt_flags |= MNT_NODEV;
    if (flags & MS_NOEXEC)
        mnt_flags |= MNT_NOEXEC;
    if (flags & MS_NOATIME)
        mnt_flags |= MNT_NOATIME;
    if (flags & MS_NODIRATIME)
        mnt_flags |= MNT_NODIRATIME;
    if (flags & MS_STRICTATIME)
        mnt_flags &= ~(MNT_RELATIME | MNT_NOATIME);
    if (flags & MS_RDONLY)
        mnt_flags |= MNT_READONLY;
    if (flags & MS_NOSYMFOLLOW)
        mnt_flags |= MNT_NOSYMFOLLOW;

    /* The default atime for remount is preservation */
    if ((flags & MS_REMOUNT) &&
        ((flags & (MS_NOATIME | MS_NODIRATIME |
                   MS_RELATIME | MS_STRICTATIME)) == 0)) {
        mnt_flags &= ~MNT_ATIME_MASK;
        mnt_flags |= path->mnt->mnt_flags & MNT_ATIME_MASK;
    }

    sb_flags = flags & (SB_RDONLY | SB_SYNCHRONOUS | SB_MANDLOCK | SB_DIRSYNC |
                        SB_SILENT | SB_POSIXACL | SB_LAZYTIME | SB_I_VERSION);

    if ((flags & (MS_REMOUNT | MS_BIND)) == (MS_REMOUNT | MS_BIND))
        return do_reconfigure_mnt(path, mnt_flags);
    if (flags & MS_REMOUNT)
        return do_remount(path, flags, sb_flags, mnt_flags, data_page);
    if (flags & MS_BIND)
        return do_loopback(path, dev_name, flags & MS_REC);
    if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
        return do_change_type(path, flags);
    if (flags & MS_MOVE)
        return do_move_mount_old(path, dev_name);

    return do_new_mount(path, type_page, sb_flags, mnt_flags,
                        dev_name, data_page);
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
    printk("%s: OK!\n", __func__);
}
