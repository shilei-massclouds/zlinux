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
#endif
#include <linux/namei.h>
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

#include "pnode.h"
#include "internal.h"

/* Maximum number of mounts in a mount namespace */
static unsigned int sysctl_mount_max __read_mostly = 100000;

enum umount_tree_flags {
    UMOUNT_SYNC = 1,
    UMOUNT_PROPAGATE = 2,
    UMOUNT_CONNECTED = 4,
};

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
static DECLARE_RWSEM(namespace_sem);
static HLIST_HEAD(unmounted);   /* protected by namespace_sem */
static LIST_HEAD(ex_mountpoints); /* protected by namespace_sem */

/*
 * vfsmount lock may be taken for read to prevent changes to the
 * vfsmount hash, ie. during mountpoint lookups or walking back
 * up the tree.
 *
 * It should be taken for write in all cases where the vfsmount
 * tree or hash is modified or when a vfsmount structure is modified.
 */
__cacheline_aligned_in_smp DEFINE_SEQLOCK(mount_lock);

static void put_mountpoint(struct mountpoint *mp);
static struct mountpoint *lock_mount(struct path *path);
static void unlock_mount(struct mountpoint *where);

static inline struct hlist_head *
m_hash(struct vfsmount *mnt, struct dentry *dentry)
{
    unsigned long tmp = ((unsigned long)mnt / L1_CACHE_BYTES);
    tmp += ((unsigned long)dentry / L1_CACHE_BYTES);
    tmp = tmp + (tmp >> m_hash_shift);
    return &mount_hashtable[tmp & m_hash_mask];
}

static inline struct hlist_head *mp_hash(struct dentry *dentry)
{
    unsigned long tmp = ((unsigned long)dentry / L1_CACHE_BYTES);
    tmp = tmp + (tmp >> mp_hash_shift);
    return &mountpoint_hashtable[tmp & mp_hash_mask];
}

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
    init_waitqueue_head(&new_ns->poll);
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

static inline int check_mnt(struct mount *mnt)
{
    return mnt->mnt_ns == current->nsproxy->mnt_ns;
}

static void mntput_no_expire(struct mount *mnt)
{
    LIST_HEAD(list);
    int count;

    rcu_read_lock();
    if (likely(READ_ONCE(mnt->mnt_ns))) {
        /*
         * Since we don't do lock_mount_hash() here,
         * ->mnt_ns can change under us.  However, if it's
         * non-NULL, then there's a reference that won't
         * be dropped until after an RCU delay done after
         * turning ->mnt_ns NULL.  So if we observe it
         * non-NULL under rcu_read_lock(), the reference
         * we are dropping is not the final one.
         */
        mnt_add_count(mnt, -1);
        rcu_read_unlock();
        return;
    }

    panic("%s: END!\n", __func__);
}

static void free_mnt_ns(struct mnt_namespace *ns)
{
#if 0
    if (!is_anon_ns(ns))
        ns_free_inum(&ns->ns);
    dec_mnt_namespaces(ns->ucounts);
    put_user_ns(ns->user_ns);
    kfree(ns);
#endif
    panic("%s: END!\n", __func__);
}

static struct mount *next_mnt(struct mount *p, struct mount *root)
{
    struct list_head *next = p->mnt_mounts.next;
    if (next == &p->mnt_mounts) {
        while (1) {
            if (p == root)
                return NULL;
            next = p->mnt_child.next;
            if (next != &p->mnt_parent->mnt_mounts)
                break;
            p = p->mnt_parent;
        }
    }
    return list_entry(next, struct mount, mnt_child);
}

static inline int tree_contains_unbindable(struct mount *mnt)
{
    struct mount *p;
    for (p = mnt; p; p = next_mnt(p, mnt)) {
        if (IS_MNT_UNBINDABLE(p))
            return 1;
    }
    return 0;
}

static bool is_mnt_ns_file(struct dentry *dentry)
{
#if 0
    /* Is this a proxy for a mount namespace? */
    return dentry->d_op == &ns_dentry_operations &&
           dentry->d_fsdata == &mntns_operations;
#endif
    panic("%s: END!\n", __func__);
}

static bool mnt_ns_loop(struct dentry *dentry)
{
#if 0
    /* Could bind mounting the mount namespace inode cause a
     * mount namespace loop?
     */
    struct mnt_namespace *mnt_ns;
    if (!is_mnt_ns_file(dentry))
        return false;

    mnt_ns = to_mnt_ns(get_proc_ns(dentry->d_inode));
    return current->nsproxy->mnt_ns->seq >= mnt_ns->seq;
#endif
    panic("%s: END!\n", __func__);
}

/*
 * Check that there aren't references to earlier/same mount namespaces in the
 * specified subtree.  Such references can act as pins for mount namespaces
 * that aren't checked by the mount-cycle checking code, thereby allowing
 * cycles to be made.
 */
static bool check_for_nsfs_mounts(struct mount *subtree)
{
    struct mount *p;
    bool ret = false;

    lock_mount_hash();
    for (p = subtree; p; p = next_mnt(p, subtree))
        if (mnt_ns_loop(p->mnt.mnt_root))
            goto out;

    ret = true;
out:
    unlock_mount_hash();
    return ret;
}

/*
 * find the first mount at @dentry on vfsmount @mnt.
 * call under rcu_read_lock()
 */
struct mount *__lookup_mnt(struct vfsmount *mnt, struct dentry *dentry)
{
    struct hlist_head *head = m_hash(mnt, dentry);
    struct mount *p;

    hlist_for_each_entry_rcu(p, head, mnt_hash)
        if (&p->mnt_parent->mnt == mnt && p->mnt_mountpoint == dentry)
            return p;
    return NULL;
}

/*
 * lookup_mnt - Return the first child mount mounted at path
 *
 * "First" means first mounted chronologically.  If you create the
 * following mounts:
 *
 * mount /dev/sda1 /mnt
 * mount /dev/sda2 /mnt
 * mount /dev/sda3 /mnt
 *
 * Then lookup_mnt() on the base /mnt dentry in the root mount will
 * return successively the root dentry and vfsmount of /dev/sda1, then
 * /dev/sda2, then /dev/sda3, then NULL.
 *
 * lookup_mnt takes a reference to the found vfsmount.
 */
struct vfsmount *lookup_mnt(const struct path *path)
{
    struct mount *child_mnt;
    struct vfsmount *m;
    unsigned seq;

    rcu_read_lock();
#if 0
    do {
        seq = read_seqbegin(&mount_lock);
        child_mnt = __lookup_mnt(path->mnt, path->dentry);
        m = child_mnt ? &child_mnt->mnt : NULL;
    } while (!legitimize_mnt(m, seq));
#else
    child_mnt = __lookup_mnt(path->mnt, path->dentry);
    m = child_mnt ? &child_mnt->mnt : NULL;
#endif
    rcu_read_unlock();
    return m;
}

static void namespace_unlock(void)
{
    struct hlist_head head;
    struct hlist_node *p;
    struct mount *m;
    LIST_HEAD(list);

    hlist_move_list(&unmounted, &head);
    list_splice_init(&ex_mountpoints, &list);

    up_write(&namespace_sem);

    //shrink_dentry_list(&list);

    if (likely(hlist_empty(&head)))
        return;

    //synchronize_rcu_expedited();

    hlist_for_each_entry_safe(m, p, &head, mnt_umount) {
        hlist_del(&m->mnt_umount);
        mntput(&m->mnt);
    }
}

static inline void namespace_lock(void)
{
    down_write(&namespace_sem);
}

static struct mountpoint *get_mountpoint(struct dentry *dentry)
{
    struct mountpoint *mp, *new = NULL;
    int ret;

    if (d_mountpoint(dentry)) {
        /* might be worth a WARN_ON() */
        if (d_unlinked(dentry))
            return ERR_PTR(-ENOENT);

     mountpoint:
#if 0
        read_seqlock_excl(&mount_lock);
        mp = lookup_mountpoint(dentry);
        read_sequnlock_excl(&mount_lock);
        if (mp)
            goto done;
#endif
        panic("%s: d_mountpoint!\n", __func__);
    }

    if (!new)
        new = kmalloc(sizeof(struct mountpoint), GFP_KERNEL);
    if (!new)
        return ERR_PTR(-ENOMEM);

    /* Exactly one processes may set d_mounted */
    ret = d_set_mounted(dentry);

    /* Someone else set d_mounted? */
    if (ret == -EBUSY)
        goto mountpoint;

    /* The dentry is not available as a mountpoint? */
    mp = ERR_PTR(ret);
    if (ret)
        goto done;

    /* Add the new mountpoint to the hash table */
    read_seqlock_excl(&mount_lock);
    new->m_dentry = dget(dentry);
    new->m_count = 1;
    hlist_add_head(&new->m_hash, mp_hash(dentry));
    INIT_HLIST_HEAD(&new->m_list);
    read_sequnlock_excl(&mount_lock);

    mp = new;
    new = NULL;

 done:
    kfree(new);
    return mp;
}

static void unlock_mount(struct mountpoint *where)
{
    struct dentry *dentry = where->m_dentry;

    read_seqlock_excl(&mount_lock);
    put_mountpoint(where);
    read_sequnlock_excl(&mount_lock);

    namespace_unlock();
    inode_unlock(dentry->d_inode);
}

static struct mountpoint *lock_mount(struct path *path)
{
    struct vfsmount *mnt;
    struct dentry *dentry = path->dentry;
 retry:
    inode_lock(dentry->d_inode);
    if (unlikely(cant_mount(dentry))) {
        inode_unlock(dentry->d_inode);
        return ERR_PTR(-ENOENT);
    }
    namespace_lock();
    mnt = lookup_mnt(path);
    if (likely(!mnt)) {
        struct mountpoint *mp = get_mountpoint(dentry);
        if (IS_ERR(mp)) {
            namespace_unlock();
            inode_unlock(dentry->d_inode);
            return mp;
        }
        return mp;
    }
    namespace_unlock();

    panic("%s: END!\n", __func__);
}

/*
 * vfsmount lock must be held.  Additionally, the caller is responsible
 * for serializing calls for given disposal list.
 */
static void __put_mountpoint(struct mountpoint *mp, struct list_head *list)
{
    if (!--mp->m_count) {
        struct dentry *dentry = mp->m_dentry;
        BUG_ON(!hlist_empty(&mp->m_list));
        spin_lock(&dentry->d_lock);
        dentry->d_flags &= ~DCACHE_MOUNTED;
        spin_unlock(&dentry->d_lock);
        dput_to_list(dentry, list);
        hlist_del(&mp->m_hash);
        kfree(mp);
    }
}

/* called with namespace_lock and vfsmount lock */
static void put_mountpoint(struct mountpoint *mp)
{
    __put_mountpoint(mp, &ex_mountpoints);
}

/*
 * mount_lock must be held
 * namespace_sem must be held for write
 */
static void umount_tree(struct mount *mnt, enum umount_tree_flags how)
{
    panic("%s: END!\n", __func__);
}

static void cleanup_group_ids(struct mount *mnt, struct mount *end)
{
    struct mount *p;

    for (p = mnt; p != end; p = next_mnt(p, mnt)) {
        if (p->mnt_group_id && !IS_MNT_SHARED(p))
            mnt_release_group_id(p);
    }
}

/*
 * Release a peer group ID
 */
void mnt_release_group_id(struct mount *mnt)
{
    ida_free(&mnt_group_ida, mnt->mnt_group_id);
    mnt->mnt_group_id = 0;
}

int count_mounts(struct mnt_namespace *ns, struct mount *mnt)
{
    unsigned int max = READ_ONCE(sysctl_mount_max);
    unsigned int mounts = 0;
    struct mount *p;

    if (ns->mounts >= max)
        return -ENOSPC;
    max -= ns->mounts;
    if (ns->pending_mounts >= max)
        return -ENOSPC;
    max -= ns->pending_mounts;

    for (p = mnt; p; p = next_mnt(p, mnt))
        mounts++;

    if (mounts > max)
        return -ENOSPC;

    ns->pending_mounts += mounts;
    return 0;
}

/*
 * vfsmount lock must be held for write
 */
void mnt_set_mountpoint(struct mount *mnt,
                        struct mountpoint *mp,
                        struct mount *child_mnt)
{
    mp->m_count++;
    mnt_add_count(mnt, 1);  /* essentially, that's mntget */
    child_mnt->mnt_mountpoint = mp->m_dentry;
    child_mnt->mnt_parent = mnt;
    child_mnt->mnt_mp = mp;
    hlist_add_head(&child_mnt->mnt_mp_list, &mp->m_list);
}

static void __attach_mnt(struct mount *mnt, struct mount *parent)
{
    hlist_add_head_rcu(&mnt->mnt_hash,
                       m_hash(&parent->mnt, mnt->mnt_mountpoint));
    list_add_tail(&mnt->mnt_child, &parent->mnt_mounts);
}

/*
 * vfsmount lock must be held for write
 */
static void touch_mnt_namespace(struct mnt_namespace *ns)
{
    if (ns) {
        //ns->event = ++event;
        wake_up_interruptible(&ns->poll);
    }
}

/*
 * vfsmount lock must be held for write
 */
static void commit_tree(struct mount *mnt)
{
    struct mount *parent = mnt->mnt_parent;
    struct mount *m;
    LIST_HEAD(head);
    struct mnt_namespace *n = parent->mnt_ns;

    BUG_ON(parent == mnt);

    list_add_tail(&head, &mnt->mnt_list);
    list_for_each_entry(m, &head, mnt_list)
        m->mnt_ns = n;

    list_splice(&head, n->list.prev);

    n->mounts += n->pending_mounts;
    n->pending_mounts = 0;

    __attach_mnt(mnt, parent);
    touch_mnt_namespace(n);
}

/*
 * vfsmount lock must be held for write
 */
static struct mountpoint *unhash_mnt(struct mount *mnt)
{
    struct mountpoint *mp;
    mnt->mnt_parent = mnt;
    mnt->mnt_mountpoint = mnt->mnt.mnt_root;
    list_del_init(&mnt->mnt_child);
    hlist_del_init_rcu(&mnt->mnt_hash);
    hlist_del_init(&mnt->mnt_mp_list);
    mp = mnt->mnt_mp;
    mnt->mnt_mp = NULL;
    return mp;
}

/*
 * vfsmount lock must be held for write
 */
static void attach_mnt(struct mount *mnt,
                       struct mount *parent,
                       struct mountpoint *mp)
{
    mnt_set_mountpoint(parent, mp, mnt);
    __attach_mnt(mnt, parent);
}

/*
 *  @source_mnt : mount tree to be attached
 *  @nd         : place the mount tree @source_mnt is attached
 *  @parent_nd  : if non-null, detach the source_mnt from its parent and
 *             store the parent mount and mountpoint dentry.
 *             (done when source_mnt is moved)
 *
 *  NOTE: in the table below explains the semantics when a source mount
 *  of a given type is attached to a destination mount of a given type.
 * ---------------------------------------------------------------------------
 * |         BIND MOUNT OPERATION                                            |
 * |**************************************************************************
 * | source-->| shared        |       private  |       slave    | unbindable |
 * | dest     |               |                |                |            |
 * |   |      |               |                |                |            |
 * |   v      |               |                |                |            |
 * |**************************************************************************
 * |  shared  | shared (++)   |     shared (+) |     shared(+++)|  invalid   |
 * |          |               |                |                |            |
 * |non-shared| shared (+)    |      private   |      slave (*) |  invalid   |
 * ***************************************************************************
 * A bind operation clones the source mount and mounts the clone on the
 * destination mount.
 *
 * (++)  the cloned mount is propagated to all the mounts in the propagation
 *   tree of the destination mount and the cloned mount is added to
 *   the peer group of the source mount.
 * (+)   the cloned mount is created under the destination mount and is marked
 *       as shared. The cloned mount is added to the peer group of the source
 *       mount.
 * (+++) the mount is propagated to all the mounts in the propagation tree
 *       of the destination mount and the cloned mount is made slave
 *       of the same master as that of the source mount. The cloned mount
 *       is marked as 'shared and slave'.
 * (*)   the cloned mount is made a slave of the same master as that of the
 *   source mount.
 *
 * ---------------------------------------------------------------------------
 * |                MOVE MOUNT OPERATION                                 |
 * |**************************************************************************
 * | source-->| shared        |       private  |       slave    | unbindable |
 * | dest     |               |                |                |            |
 * |   |      |               |                |                |            |
 * |   v      |               |                |                |            |
 * |**************************************************************************
 * |  shared  | shared (+)    |     shared (+) |    shared(+++) |  invalid   |
 * |          |               |                |                |            |
 * |non-shared| shared (+*)   |      private   |    slave (*)   | unbindable |
 * ***************************************************************************
 *
 * (+)  the mount is moved to the destination. And is then propagated to
 *  all the mounts in the propagation tree of the destination mount.
 * (+*)  the mount is moved to the destination.
 * (+++)  the mount is moved to the destination and is then propagated to
 *  all the mounts belonging to the destination mount's propagation tree.
 *  the mount is marked as 'shared and slave'.
 * (*)  the mount continues to be a slave at the new location.
 *
 * if the source mount is a tree, the operations explained above is
 * applied to each mount in the tree.
 * Must be called without spinlocks held, since this function can sleep
 * in allocations.
 */
static int attach_recursive_mnt(struct mount *source_mnt,
                                struct mount *dest_mnt,
                                struct mountpoint *dest_mp,
                                bool moving)
{
    struct user_namespace *user_ns = current->nsproxy->mnt_ns->user_ns;
    HLIST_HEAD(tree_list);
    struct mnt_namespace *ns = dest_mnt->mnt_ns;
    struct mountpoint *smp;
    struct mount *child, *p;
    struct hlist_node *n;
    int err;

    /* Preallocate a mountpoint in case the new mounts need
     * to be tucked under other mounts.
     */
    smp = get_mountpoint(source_mnt->mnt.mnt_root);
    if (IS_ERR(smp))
        return PTR_ERR(smp);

    /* Is there space to add these mounts to the mount namespace? */
    if (!moving) {
        err = count_mounts(ns, source_mnt);
        if (err)
            goto out;
    }

    if (IS_MNT_SHARED(dest_mnt)) {
#if 0
        err = invent_group_ids(source_mnt, true);
        if (err)
            goto out;
        err = propagate_mnt(dest_mnt, dest_mp, source_mnt, &tree_list);
        lock_mount_hash();
        if (err)
            goto out_cleanup_ids;
        for (p = source_mnt; p; p = next_mnt(p, source_mnt))
            set_mnt_shared(p);
#endif
        panic("%s: IS_MNT_SHARED!\n", __func__);
    } else {
        lock_mount_hash();
    }
    if (moving) {
        unhash_mnt(source_mnt);
        attach_mnt(source_mnt, dest_mnt, dest_mp);
        touch_mnt_namespace(source_mnt->mnt_ns);
    } else {
        if (source_mnt->mnt_ns) {
            /* move from anon - the caller will destroy */
            list_del_init(&source_mnt->mnt_ns->list);
        }
        mnt_set_mountpoint(dest_mnt, dest_mp, source_mnt);
        commit_tree(source_mnt);
    }

    hlist_for_each_entry_safe(child, n, &tree_list, mnt_hash) {
        panic("%s: 1!\n", __func__);
    }
    put_mountpoint(smp);
    unlock_mount_hash();

    return 0;

 out_cleanup_ids:
    while (!hlist_empty(&tree_list)) {
        child = hlist_entry(tree_list.first, struct mount, mnt_hash);
        child->mnt_parent->mnt_ns->pending_mounts = 0;
        umount_tree(child, UMOUNT_SYNC);
    }
    unlock_mount_hash();
    cleanup_group_ids(source_mnt, NULL);
 out:
    ns->pending_mounts = 0;

    read_seqlock_excl(&mount_lock);
    put_mountpoint(smp);
    read_sequnlock_excl(&mount_lock);

    return err;
}

static int graft_tree(struct mount *mnt, struct mount *p, struct mountpoint *mp)
{
    if (mnt->mnt.mnt_sb->s_flags & SB_NOUSER)
        return -EINVAL;

    if (d_is_dir(mp->m_dentry) != d_is_dir(mnt->mnt.mnt_root))
        return -ENOTDIR;

    return attach_recursive_mnt(mnt, p, mp, false);
}

/*
 * add a mount into a namespace's mount tree
 */
static int do_add_mount(struct mount *newmnt, struct mountpoint *mp,
                        const struct path *path, int mnt_flags)
{
    struct mount *parent = real_mount(path->mnt);

    mnt_flags &= ~MNT_INTERNAL_FLAGS;

    if (unlikely(!check_mnt(parent))) {
        /* that's acceptable only for automounts done in private ns */
        if (!(mnt_flags & MNT_SHRINKABLE))
            return -EINVAL;
        /* ... and for those we'd better have mountpoint still alive */
        if (!parent->mnt_ns)
            return -EINVAL;
    }

    /* Refuse the same filesystem on the same mount point */
    if (path->mnt->mnt_sb == newmnt->mnt.mnt_sb &&
        path->mnt->mnt_root == path->dentry)
        return -EBUSY;

    if (d_is_symlink(newmnt->mnt.mnt_root))
        return -EINVAL;

    newmnt->mnt.mnt_flags = mnt_flags;
    return graft_tree(newmnt, parent, mp);
}

/*
 * Create a new mount using a superblock configuration and request it
 * be added to the namespace tree.
 */
static int do_new_mount_fc(struct fs_context *fc, struct path *mountpoint,
                           unsigned int mnt_flags)
{
    struct vfsmount *mnt;
    struct mountpoint *mp;
    struct super_block *sb = fc->root->d_sb;
    int error;

#if 0
    if (mount_too_revealing(sb, &mnt_flags))
        error = -EPERM;
#endif

    if (unlikely(error)) {
        fc_drop_locked(fc);
        return error;
    }

    up_write(&sb->s_umount);

    mnt = vfs_create_mount(fc);
    if (IS_ERR(mnt))
        return PTR_ERR(mnt);

    //mnt_warn_timestamp_expiry(mountpoint, mnt);

    mp = lock_mount(mountpoint);
    if (IS_ERR(mp)) {
        mntput(mnt);
        return PTR_ERR(mp);
    }
    error = do_add_mount(real_mount(mnt), mp, mountpoint, mnt_flags);
    unlock_mount(mp);
    if (error < 0)
        mntput(mnt);
    return error;
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

static int do_move_mount(struct path *old_path, struct path *new_path)
{
    struct mnt_namespace *ns;
    struct mount *p;
    struct mount *old;
    struct mount *parent;
    struct mountpoint *mp, *old_mp;
    int err;
    bool attached;

    mp = lock_mount(new_path);
    if (IS_ERR(mp))
        return PTR_ERR(mp);

    old = real_mount(old_path->mnt);
    p = real_mount(new_path->mnt);
    parent = old->mnt_parent;
    attached = mnt_has_parent(old);
    old_mp = old->mnt_mp;
    ns = old->mnt_ns;

    err = -EINVAL;
    /* The mountpoint must be in our namespace. */
    if (!check_mnt(p))
        goto out;

    /* The thing moved must be mounted... */
    if (!is_mounted(&old->mnt))
        goto out;

#if 0
    /* ... and either ours or the root of anon namespace */
    if (!(attached ? check_mnt(old) : is_anon_ns(ns)))
        goto out;
#endif

    if (old->mnt.mnt_flags & MNT_LOCKED)
        goto out;

    if (old_path->dentry != old_path->mnt->mnt_root)
        goto out;

    if (d_is_dir(new_path->dentry) !=
        d_is_dir(old_path->dentry))
        goto out;
    /*
     * Don't move a mount residing in a shared parent.
     */
    if (attached && IS_MNT_SHARED(parent))
        goto out;
    /*
     * Don't move a mount tree containing unbindable mounts to a destination
     * mount which is shared.
     */
    if (IS_MNT_SHARED(p) && tree_contains_unbindable(old))
        goto out;
    err = -ELOOP;
#if 0
    if (!check_for_nsfs_mounts(old))
        goto out;
#endif
    for (; mnt_has_parent(p); p = p->mnt_parent)
        if (p == old)
            goto out;

    err = attach_recursive_mnt(old, real_mount(new_path->mnt), mp, attached);
    if (err)
        goto out;

    /* if the mount is moved, it should no longer be expire
     * automatically */
    list_del_init(&old->mnt_expire);
    if (attached)
        put_mountpoint(old_mp);

 out:
    unlock_mount(mp);
    if (!err) {
        if (attached)
            mntput_no_expire(parent);
        else
            free_mnt_ns(ns);
    }
    return err;
}

static int do_move_mount_old(struct path *path, const char *old_name)
{
    struct path old_path;
    int err;

    if (!old_name || !*old_name)
        return -EINVAL;

    err = kern_path(old_name, LOOKUP_FOLLOW, &old_path);
    if (err)
        return err;

    err = do_move_mount(&old_path, path);
    path_put(&old_path);
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
