// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/super.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  super.c contains code to handle: - mount structures
 *                                   - super-block tables
 *                                   - filesystem drivers list
 *                                   - mount system call
 *                                   - umount system call
 *                                   - ustat system call
 *
 * GK 2/5/95  -  Changed to support mounting the root fs via NFS
 *
 *  Added kerneld support: Jacques Gelinas and Bjorn Ekwall
 *  Added change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Added options to /proc/mounts:
 *    Torbjörn Lindh (torbjorn.lindh@gopta.se), April 14, 1996.
 *  Added devfs support: Richard Gooch <rgooch@atnf.csiro.au>, 13-JAN-1998
 *  Heavily rewritten for 'one fs - one tree' dcache architecture. AV, Mar 2000
 */

#include <linux/export.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#if 0
#include <linux/mount.h>
#include <linux/security.h>
#endif
#include <linux/writeback.h>        /* for the emergency remount stuff */
#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/backing-dev.h>
#if 0
#include <linux/rculist_bl.h>
#include <linux/fscrypt.h>
#include <linux/fsnotify.h>
#include <uapi/linux/mount.h>
#endif
#include <linux/user_namespace.h>
#include <linux/fs_context.h>
#include "internal.h"

static LIST_HEAD(super_blocks);
static DEFINE_SPINLOCK(sb_lock);

static DEFINE_IDA(unnamed_dev_ida);

void kill_anon_super(struct super_block *sb)
{
#if 0
    dev_t dev = sb->s_dev;
    generic_shutdown_super(sb);
    free_anon_bdev(dev);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(kill_anon_super);

/**
 * vfs_get_tree - Get the mountable root
 * @fc: The superblock configuration context.
 *
 * The filesystem is invoked to get or create a superblock which can then later
 * be used for mounting.  The filesystem places a pointer to the root to be
 * used for mounting in @fc->root.
 */
int vfs_get_tree(struct fs_context *fc)
{
    struct super_block *sb;
    int error;

    if (fc->root)
        return -EBUSY;

    /* Get the mountable root in fc->root, with a ref on the root and a ref
     * on the superblock.
     */
    error = fc->ops->get_tree(fc);
    if (error < 0)
        return error;

    if (!fc->root) {
        pr_err("Filesystem %s get_tree() didn't set fc->root\n",
               fc->fs_type->name);
        /* We don't know what the locking state of the superblock is -
         * if there is a superblock.
         */
        BUG();
    }

    sb = fc->root->d_sb;
    WARN_ON(!sb->s_bdi);

    /*
     * Write barrier is for super_cache_count(). We place it before setting
     * SB_BORN as the data dependency between the two functions is the
     * superblock structure contents that we just set up, not the SB_BORN
     * flag.
     */
    smp_wmb();
    sb->s_flags |= SB_BORN;

    /*
     * filesystems should never set s_maxbytes larger than MAX_LFS_FILESIZE
     * but s_maxbytes was an unsigned long long for many releases. Throw
     * this warning for a little while to try and catch filesystems that
     * violate this rule.
     */
    WARN((sb->s_maxbytes < 0), "%s set sb->s_maxbytes to "
         "negative value (%lld)\n", fc->fs_type->name, sb->s_maxbytes);

    return 0;
}
EXPORT_SYMBOL(vfs_get_tree);

int get_tree_nodev(struct fs_context *fc,
                   int (*fill_super)(struct super_block *sb,
                                     struct fs_context *fc))
{
    return vfs_get_super(fc, vfs_get_independent_super, fill_super);
}
EXPORT_SYMBOL(get_tree_nodev);

static void destroy_super_work(struct work_struct *work)
{
#if 0
    struct super_block *s =
        container_of(work, struct super_block, destroy_work);
    int i;

    for (i = 0; i < SB_FREEZE_LEVELS; i++)
        percpu_free_rwsem(&s->s_writers.rw_sem[i]);
    kfree(s);
#endif
    panic("%s: END!\n", __func__);
}

/* Free a superblock that has never been seen by anyone */
static void destroy_unused_super(struct super_block *s)
{
    if (!s)
        return;
    up_write(&s->s_umount);
    panic("%s: END!\n", __func__);
#if 0
    list_lru_destroy(&s->s_dentry_lru);
    list_lru_destroy(&s->s_inode_lru);
    security_sb_free(s);
    put_user_ns(s->s_user_ns);
    kfree(s->s_subtype);
    free_prealloced_shrinker(&s->s_shrink);
    /* no delays needed */
    destroy_super_work(&s->destroy_work);
#endif
}

/**
 *  grab_super - acquire an active reference
 *  @s: reference we are trying to make active
 *
 *  Tries to acquire an active reference.  grab_super() is used when we
 *  had just found a superblock in super_blocks or fs_type->fs_supers
 *  and want to turn it into a full-blown active reference.  grab_super()
 *  is called with sb_lock held and drops it.  Returns 1 in case of
 *  success, 0 if we had failed (superblock contents was already dead or
 *  dying when grab_super() had been called).  Note that this is only
 *  called for superblocks not in rundown mode (== ones still on ->fs_supers
 *  of their type), so increment of ->s_count is OK here.
 */
static int grab_super(struct super_block *s) __releases(sb_lock)
{
#if 0
    s->s_count++;
    spin_unlock(&sb_lock);
    down_write(&s->s_umount);
    if ((s->s_flags & SB_BORN) && atomic_inc_not_zero(&s->s_active)) {
        put_super(s);
        return 1;
    }
    up_write(&s->s_umount);
    put_super(s);
#endif
    panic("%s: END!\n", __func__);
    return 0;
}

/**
 *  alloc_super -   create new superblock
 *  @type:  filesystem type superblock should belong to
 *  @flags: the mount flags
 *  @user_ns: User namespace for the super_block
 *
 *  Allocates and initializes a new &struct super_block.  alloc_super()
 *  returns a pointer new superblock or %NULL if allocation had failed.
 */
static struct super_block *alloc_super(struct file_system_type *type, int flags,
                                       struct user_namespace *user_ns)
{
    struct super_block *s = kzalloc(sizeof(struct super_block), GFP_USER);
    static const struct super_operations default_op;
    int i;

    if (!s)
        return NULL;

    INIT_LIST_HEAD(&s->s_mounts);
    s->s_user_ns = get_user_ns(user_ns);
    init_rwsem(&s->s_umount);
    /*
     * sget() can have s_umount recursion.
     *
     * When it cannot find a suitable sb, it allocates a new
     * one (this one), and tries again to find a suitable old
     * one.
     *
     * In case that succeeds, it will acquire the s_umount
     * lock of the old one. Since these are clearly distrinct
     * locks, and this object isn't exposed yet, there's no
     * risk of deadlocks.
     *
     * Annotate this by putting this lock in a different
     * subclass.
     */
    down_write_nested(&s->s_umount, SINGLE_DEPTH_NESTING);

#if 0
    for (i = 0; i < SB_FREEZE_LEVELS; i++) {
        if (__percpu_init_rwsem(&s->s_writers.rw_sem[i],
                                sb_writers_name[i],
                                &type->s_writers_key[i]))
            goto fail;
    }
    init_waitqueue_head(&s->s_writers.wait_unfrozen);
#endif
    s->s_bdi = &noop_backing_dev_info;
    s->s_flags = flags;
    if (s->s_user_ns != &init_user_ns)
        s->s_iflags |= SB_I_NODEV;
    INIT_HLIST_NODE(&s->s_instances);
    INIT_HLIST_BL_HEAD(&s->s_roots);
    mutex_init(&s->s_sync_lock);
    INIT_LIST_HEAD(&s->s_inodes);
    spin_lock_init(&s->s_inode_list_lock);
    INIT_LIST_HEAD(&s->s_inodes_wb);
    spin_lock_init(&s->s_inode_wblist_lock);

    s->s_count = 1;
    atomic_set(&s->s_active, 1);
    mutex_init(&s->s_vfs_rename_mutex);
    //init_rwsem(&s->s_dquot.dqio_sem);
    s->s_maxbytes = MAX_NON_LFS;
    s->s_op = &default_op;
    s->s_time_gran = 1000000000;
    s->s_time_min = TIME64_MIN;
    s->s_time_max = TIME64_MAX;

#if 0
    s->s_shrink.seeks = DEFAULT_SEEKS;
    s->s_shrink.scan_objects = super_cache_scan;
    s->s_shrink.count_objects = super_cache_count;
    s->s_shrink.batch = 1024;
    s->s_shrink.flags = SHRINKER_NUMA_AWARE | SHRINKER_MEMCG_AWARE;
    if (prealloc_shrinker(&s->s_shrink))
        goto fail;
    if (list_lru_init_memcg(&s->s_dentry_lru, &s->s_shrink))
        goto fail;
    if (list_lru_init_memcg(&s->s_inode_lru, &s->s_shrink))
        goto fail;
#endif
    return s;

fail:
    destroy_unused_super(s);
    return NULL;
}

/**
 * sget_fc - Find or create a superblock
 * @fc: Filesystem context.
 * @test: Comparison callback
 * @set: Setup callback
 *
 * Find or create a superblock using the parameters stored in the filesystem
 * context and the two callback functions.
 *
 * If an extant superblock is matched, then that will be returned with an
 * elevated reference count that the caller must transfer or discard.
 *
 * If no match is made, a new superblock will be allocated and basic
 * initialisation will be performed (s_type, s_fs_info and s_id will be set and
 * the set() callback will be invoked), the superblock will be published and it
 * will be returned in a partially constructed state with SB_BORN and SB_ACTIVE
 * as yet unset.
 */
struct super_block *
sget_fc(struct fs_context *fc,
        int (*test)(struct super_block *, struct fs_context *),
        int (*set)(struct super_block *, struct fs_context *))
{
    struct super_block *s = NULL;
    struct super_block *old;
    struct user_namespace *user_ns = fc->global ? &init_user_ns : fc->user_ns;
    int err;

retry:
    spin_lock(&sb_lock);
    if (test) {
        hlist_for_each_entry(old, &fc->fs_type->fs_supers, s_instances) {
            if (test(old, fc))
                goto share_extant_sb;
        }
    }
    if (!s) {
        spin_unlock(&sb_lock);
        s = alloc_super(fc->fs_type, fc->sb_flags, user_ns);
        if (!s)
            return ERR_PTR(-ENOMEM);
        goto retry;
    }

    s->s_fs_info = fc->s_fs_info;
    err = set(s, fc);
    if (err) {
        s->s_fs_info = NULL;
        spin_unlock(&sb_lock);
        destroy_unused_super(s);
        return ERR_PTR(err);
    }

    fc->s_fs_info = NULL;
    s->s_type = fc->fs_type;
    s->s_iflags |= fc->s_iflags;
    strlcpy(s->s_id, s->s_type->name, sizeof(s->s_id));
    list_add_tail(&s->s_list, &super_blocks);
    hlist_add_head(&s->s_instances, &s->s_type->fs_supers);
    spin_unlock(&sb_lock);
    get_filesystem(s->s_type);
    //register_shrinker_prepared(&s->s_shrink);
    return s;

 share_extant_sb:
    if (user_ns != old->s_user_ns) {
        spin_unlock(&sb_lock);
        destroy_unused_super(s);
        return ERR_PTR(-EBUSY);
    }
    if (!grab_super(old))
        goto retry;
    destroy_unused_super(s);
    return old;
}
EXPORT_SYMBOL(sget_fc);

/**
 * get_anon_bdev - Allocate a block device for filesystems which don't have one.
 * @p: Pointer to a dev_t.
 *
 * Filesystems which don't use real block devices can call this function
 * to allocate a virtual block device.
 *
 * Context: Any context.  Frequently called while holding sb_lock.
 * Return: 0 on success, -EMFILE if there are no anonymous bdevs left
 * or -ENOMEM if memory allocation failed.
 */
int get_anon_bdev(dev_t *p)
{
    int dev;

    /*
     * Many userspace utilities consider an FSID of 0 invalid.
     * Always return at least 1 from get_anon_bdev.
     */
    dev = ida_alloc_range(&unnamed_dev_ida, 1, (1 << MINORBITS) - 1,
                          GFP_ATOMIC);
    if (dev == -ENOSPC)
        dev = -EMFILE;
    if (dev < 0)
        return dev;

    *p = MKDEV(0, dev);
    return 0;
}
EXPORT_SYMBOL(get_anon_bdev);

int set_anon_super(struct super_block *s, void *data)
{
    return get_anon_bdev(&s->s_dev);
}
EXPORT_SYMBOL(set_anon_super);

int set_anon_super_fc(struct super_block *sb, struct fs_context *fc)
{
    return set_anon_super(sb, NULL);
}
EXPORT_SYMBOL(set_anon_super_fc);

static void destroy_super_rcu(struct rcu_head *head)
{
    struct super_block *s = container_of(head, struct super_block, rcu);
#if 0
    INIT_WORK(&s->destroy_work, destroy_super_work);
    schedule_work(&s->destroy_work);
#endif
    panic("%s: END!\n", __func__);
}

/*
 * Drop a superblock's refcount.  The caller must hold sb_lock.
 */
static void __put_super(struct super_block *s)
{
    if (!--s->s_count) {
        list_del_init(&s->s_list);
        WARN_ON(s->s_dentry_lru.node);
        WARN_ON(s->s_inode_lru.node);
        WARN_ON(!list_empty(&s->s_mounts));
        put_user_ns(s->s_user_ns);
        kfree(s->s_subtype);
        call_rcu(&s->rcu, destroy_super_rcu);
    }
}

/**
 *  put_super   -   drop a temporary reference to superblock
 *  @sb: superblock in question
 *
 *  Drops a temporary reference, frees superblock if there's no
 *  references left.
 */
void put_super(struct super_block *sb)
{
    spin_lock(&sb_lock);
    __put_super(sb);
    spin_unlock(&sb_lock);
}

/**
 *  deactivate_locked_super -   drop an active reference to superblock
 *  @s: superblock to deactivate
 *
 *  Drops an active reference to superblock, converting it into a temporary
 *  one if there is no other active references left.  In that case we
 *  tell fs driver to shut it down and drop the temporary reference we
 *  had just acquired.
 *
 *  Caller holds exclusive lock on superblock; that lock is released.
 */
void deactivate_locked_super(struct super_block *s)
{
    struct file_system_type *fs = s->s_type;
    if (atomic_dec_and_test(&s->s_active)) {
        //unregister_shrinker(&s->s_shrink);
        fs->kill_sb(s);

        /*
         * Since list_lru_destroy() may sleep, we cannot call it from
         * put_super(), where we hold the sb_lock. Therefore we destroy
         * the lru lists right now.
         */
        list_lru_destroy(&s->s_dentry_lru);
        list_lru_destroy(&s->s_inode_lru);

        put_filesystem(fs);
        put_super(s);
    } else {
        up_write(&s->s_umount);
    }
}

/**
 * vfs_get_super - Get a superblock with a search key set in s_fs_info.
 * @fc: The filesystem context holding the parameters
 * @keying: How to distinguish superblocks
 * @fill_super: Helper to initialise a new superblock
 *
 * Search for a superblock and create a new one if not found.  The search
 * criterion is controlled by @keying.  If the search fails, a new superblock
 * is created and @fill_super() is called to initialise it.
 *
 * @keying can take one of a number of values:
 *
 * (1) vfs_get_single_super - Only one superblock of this type may exist on the
 *     system.  This is typically used for special system filesystems.
 *
 * (2) vfs_get_keyed_super - Multiple superblocks may exist, but they must have
 *     distinct keys (where the key is in s_fs_info).  Searching for the same
 *     key again will turn up the superblock for that key.
 *
 * (3) vfs_get_independent_super - Multiple superblocks may exist and are
 *     unkeyed.  Each call will get a new superblock.
 *
 * A permissions check is made by sget_fc() unless we're getting a superblock
 * for a kernel-internal mount or a submount.
 */
int vfs_get_super(struct fs_context *fc, enum vfs_get_super_keying keying,
                  int (*fill_super)(struct super_block *sb,
                                    struct fs_context *fc))
{
    int (*test)(struct super_block *, struct fs_context *);
    struct super_block *sb;
    int err;

    switch (keying) {
#if 0
    case vfs_get_single_super:
    case vfs_get_single_reconf_super:
        test = test_single_super;
        break;
    case vfs_get_keyed_super:
        test = test_keyed_super;
        break;
#endif
    case vfs_get_independent_super:
        test = NULL;
        break;
    default:
        BUG();
    }

    sb = sget_fc(fc, test, set_anon_super_fc);
    if (IS_ERR(sb))
        return PTR_ERR(sb);

    if (!sb->s_root) {
        err = fill_super(sb, fc);
        if (err)
            goto error;

        sb->s_flags |= SB_ACTIVE;
        fc->root = dget(sb->s_root);
    } else {
        panic("%s: has s_root!\n", __func__);
    }

    return 0;

 error:
    deactivate_locked_super(sb);
    return err;
}
EXPORT_SYMBOL(vfs_get_super);

/**
 *  deactivate_super    -   drop an active reference to superblock
 *  @s: superblock to deactivate
 *
 *  Variant of deactivate_locked_super(), except that superblock is *not*
 *  locked by caller.  If we are going to drop the final active reference,
 *  lock will be acquired prior to that.
 */
void deactivate_super(struct super_block *s)
{
    if (!atomic_add_unless(&s->s_active, -1, 1)) {
        down_write(&s->s_umount);
        deactivate_locked_super(s);
    }
}

EXPORT_SYMBOL(deactivate_super);

void kill_litter_super(struct super_block *sb)
{
#if 0
    if (sb->s_root)
        d_genocide(sb->s_root);
    kill_anon_super(sb);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(kill_litter_super);

void kill_block_super(struct super_block *sb)
{
#if 0
    struct block_device *bdev = sb->s_bdev;
    fmode_t mode = sb->s_mode;

    bdev->bd_super = NULL;
    generic_shutdown_super(sb);
    sync_blockdev(bdev);
    WARN_ON_ONCE(!(mode & FMODE_EXCL));
    blkdev_put(bdev, mode | FMODE_EXCL);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(kill_block_super);

struct dentry *mount_bdev(struct file_system_type *fs_type,
                          int flags, const char *dev_name, void *data,
                          int (*fill_super)(struct super_block *, void *, int))
{
    struct block_device *bdev;
    struct super_block *s;
    fmode_t mode = FMODE_READ | FMODE_EXCL;
    int error = 0;

    if (!(flags & SB_RDONLY))
        mode |= FMODE_WRITE;

    bdev = blkdev_get_by_path(dev_name, mode, fs_type);
    if (IS_ERR(bdev))
        return ERR_CAST(bdev);

    panic("%s: dev(%s) END!\n", __func__, dev_name);
}
EXPORT_SYMBOL(mount_bdev);
