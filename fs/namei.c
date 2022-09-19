// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * Some corrections by tytso.
 */

/* [Feb 1997 T. Schoebel-Theuer] Complete rewrite of the pathname
 * lookup logic.
 */
/* [Feb-Apr 2000, AV] Rewrite to the new namespace architecture.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#if 0
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/syscalls.h>
#endif
#include <linux/mount.h>
#if 0
#include <linux/audit.h>
#include <linux/capability.h>
#endif
#include <linux/file.h>
#include <linux/fcntl.h>
//#include <linux/device_cgroup.h>
#include <linux/fs_struct.h>
//#include <linux/posix_acl.h>
#include <linux/hash.h>
#include <linux/bitops.h>
#include <linux/init_task.h>
#include <linux/uaccess.h>

#include "internal.h"
#include "mount.h"

#define EMBEDDED_NAME_MAX   (PATH_MAX - offsetof(struct filename, iname))

#define EMBEDDED_LEVELS 2
struct nameidata {
    struct path path;
    struct qstr last;
    struct path root;
    struct inode    *inode; /* path.dentry.d_inode */
    unsigned int    flags, state;
    unsigned    seq, m_seq, r_seq;
    int     last_type;
    unsigned    depth;
    int     total_link_count;
    struct saved {
        struct path link;
        struct delayed_call done;
        const char *name;
        unsigned seq;
    } *stack, internal[EMBEDDED_LEVELS];
    struct filename *name;
    struct nameidata *saved;
    unsigned    root_seq;
    int         dfd;
    kuid_t      dir_uid;
    umode_t     dir_mode;
} __randomize_layout;

enum {WALK_TRAILING = 1, WALK_MORE = 2, WALK_NOFOLLOW = 4};

/**
 * path_get - get a reference to a path
 * @path: path to get the reference to
 *
 * Given a path increment the reference count to the dentry and the vfsmount.
 */
void path_get(const struct path *path)
{
    mntget(path->mnt);
    dget(path->dentry);
}
EXPORT_SYMBOL(path_get);

/**
 * path_put - put a reference to a path
 * @path: path to put the reference to
 *
 * Given a path decrement the reference count to the dentry and the vfsmount.
 */
void path_put(const struct path *path)
{
    dput(path->dentry);
    mntput(path->mnt);
}
EXPORT_SYMBOL(path_put);

struct filename *
getname_kernel(const char * filename)
{
    struct filename *result;
    int len = strlen(filename) + 1;

    result = __getname();
    if (unlikely(!result))
        return ERR_PTR(-ENOMEM);

    if (len <= EMBEDDED_NAME_MAX) {
        result->name = (char *)result->iname;
    } else if (len <= PATH_MAX) {
        const size_t size = offsetof(struct filename, iname[1]);
        struct filename *tmp;

        tmp = kmalloc(size, GFP_KERNEL);
        if (unlikely(!tmp)) {
            __putname(result);
            return ERR_PTR(-ENOMEM);
        }
        tmp->name = (char *)result;
        result = tmp;
    } else {
        __putname(result);
        return ERR_PTR(-ENAMETOOLONG);
    }
    memcpy((char *)result->name, filename, len);
    result->uptr = NULL;
    result->aname = NULL;
    result->refcnt = 1;

    return result;
}

void putname(struct filename *name)
{
    if (IS_ERR(name))
        return;

    BUG_ON(name->refcnt <= 0);

    if (--name->refcnt > 0)
        return;

    if (name->name != name->iname) {
        __putname(name->name);
        kfree(name);
    } else
        __putname(name);
}

#define ND_ROOT_PRESET 1
#define ND_ROOT_GRABBED 2
#define ND_JUMPED 4

static void __set_nameidata(struct nameidata *p, int dfd, struct filename *name)
{
    struct nameidata *old = current->nameidata;
    p->stack = p->internal;
    p->depth = 0;
    p->dfd = dfd;
    p->name = name;
    p->path.mnt = NULL;
    p->path.dentry = NULL;
    p->total_link_count = old ? old->total_link_count : 0;
    p->saved = old;
    current->nameidata = p;
}

static inline void
set_nameidata(struct nameidata *p, int dfd, struct filename *name,
              const struct path *root)
{
    __set_nameidata(p, dfd, name);
    p->state = 0;
    if (unlikely(root)) {
        p->state = ND_ROOT_PRESET;
        p->root = *root;
    }
}

static int set_root(struct nameidata *nd)
{
    struct fs_struct *fs = current->fs;

    /*
     * Jumping to the real root in a scoped-lookup is a BUG in namei, but we
     * still have to ensure it doesn't happen because it will cause a breakout
     * from the dirfd.
     */
    if (WARN_ON(nd->flags & LOOKUP_IS_SCOPED))
        return -ENOTRECOVERABLE;

    if (nd->flags & LOOKUP_RCU) {
        unsigned seq;

        do {
            seq = read_seqcount_begin(&fs->seq);
            nd->root = fs->root;
            nd->root_seq =
                __read_seqcount_begin(&nd->root.dentry->d_seq);
        } while (read_seqcount_retry(&fs->seq, seq));
    } else {
        get_fs_root(fs, &nd->root);
        nd->state |= ND_ROOT_GRABBED;
    }
    return 0;
}

static int nd_jump_root(struct nameidata *nd)
{
    if (unlikely(nd->flags & LOOKUP_BENEATH))
        return -EXDEV;
    if (unlikely(nd->flags & LOOKUP_NO_XDEV)) {
        /* Absolute path arguments to path_init() are allowed. */
        if (nd->path.mnt != NULL && nd->path.mnt != nd->root.mnt)
            return -EXDEV;
    }
    if (!nd->root.mnt) {
        int error = set_root(nd);
        if (error)
            return error;
    }
    if (nd->flags & LOOKUP_RCU) {
        struct dentry *d;
        nd->path = nd->root;
        d = nd->path.dentry;
        nd->inode = d->d_inode;
        nd->seq = nd->root_seq;
        if (unlikely(read_seqcount_retry(&d->d_seq, nd->seq)))
            return -ECHILD;
    } else {
        path_put(&nd->path);
        nd->path = nd->root;
        path_get(&nd->path);
        nd->inode = nd->path.dentry->d_inode;
    }
    nd->state |= ND_JUMPED;
    return 0;
}

/* must be paired with terminate_walk() */
static const char *path_init(struct nameidata *nd, unsigned flags)
{
    int error;
    const char *s = nd->name->name;

    /* LOOKUP_CACHED requires RCU, ask caller to retry */
    if ((flags & (LOOKUP_RCU | LOOKUP_CACHED)) == LOOKUP_CACHED)
        return ERR_PTR(-EAGAIN);

    if (!*s)
        flags &= ~LOOKUP_RCU;
    if (flags & LOOKUP_RCU)
        rcu_read_lock();

    nd->flags = flags;
    nd->state |= ND_JUMPED;

    nd->m_seq = __read_seqcount_begin(&mount_lock.seqcount);
    nd->r_seq = __read_seqcount_begin(&rename_lock.seqcount);
    smp_rmb();

    if (nd->state & ND_ROOT_PRESET) {
#if 0
        struct dentry *root = nd->root.dentry;
        struct inode *inode = root->d_inode;
        if (*s && unlikely(!d_can_lookup(root)))
            return ERR_PTR(-ENOTDIR);
        nd->path = nd->root;
        nd->inode = inode;
        if (flags & LOOKUP_RCU) {
            nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
            nd->root_seq = nd->seq;
        } else {
            path_get(&nd->path);
        }
        return s;
#endif
        panic("%s: [%s] ND_ROOT_PRESET!\n", __func__, s);
    }

    nd->root.mnt = NULL;

    /* Absolute pathname -- fetch the root (LOOKUP_IN_ROOT uses nd->dfd). */
    if (*s == '/' && !(flags & LOOKUP_IN_ROOT)) {
        error = nd_jump_root(nd);
        if (unlikely(error))
            return ERR_PTR(error);
        return s;
    }

    /* Relative pathname -- get the starting-point it is relative to. */
    if (nd->dfd == AT_FDCWD) {
        if (flags & LOOKUP_RCU) {
            struct fs_struct *fs = current->fs;
            unsigned seq;

            do {
                seq = read_seqcount_begin(&fs->seq);
                nd->path = fs->pwd;
                nd->inode = nd->path.dentry->d_inode;
                nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
            } while (read_seqcount_retry(&fs->seq, seq));
        } else {
            panic("%s: NOT LOOKUP_RCU!\n", __func__);
        }
    } else {
        panic("%s: NOT AT_FDCWD!\n", __func__);
    }

    /* For scoped-lookups we need to set the root to the dirfd as well. */
    if (flags & LOOKUP_IS_SCOPED) {
        nd->root = nd->path;
        if (flags & LOOKUP_RCU) {
            nd->root_seq = nd->seq;
        } else {
            path_get(&nd->root);
            nd->state |= ND_ROOT_GRABBED;
        }
    }
    return s;
}

/* Return the hash of a string of known length */
unsigned int full_name_hash(const void *salt, const char *name,
                            unsigned int len)
{
    unsigned long hash = init_name_hash(salt);
    while (len--)
        hash = partial_name_hash((unsigned char)*name++, hash);
    return end_name_hash(hash);
}
EXPORT_SYMBOL(full_name_hash);

/* Return the "hash_len" (hash and length) of a null-terminated string */
u64 hashlen_string(const void *salt, const char *name)
{
    unsigned long hash = init_name_hash(salt);
    unsigned long len = 0, c;

    c = (unsigned char)*name;
    while (c) {
        len++;
        hash = partial_name_hash(c, hash);
        c = (unsigned char)name[len];
    }
    return hashlen_create(end_name_hash(hash), len);
}
EXPORT_SYMBOL(hashlen_string);

/*
 * We know there's a real path component here of at least
 * one character.
 */
static inline u64 hash_name(const void *salt, const char *name)
{
    unsigned long hash = init_name_hash(salt);
    unsigned long len = 0, c;

    c = (unsigned char)*name;
    do {
        len++;
        hash = partial_name_hash(c, hash);
        c = (unsigned char)name[len];
    } while (c && c != '/');
    return hashlen_create(end_name_hash(hash), len);
}

static const char *handle_dots(struct nameidata *nd, int type)
{
    if (type == LAST_DOTDOT) {
        panic("%s: LAST_DOTDOT!\n", __func__);
    }
    return NULL;
}

static inline void put_link(struct nameidata *nd)
{
    struct saved *last = nd->stack + --nd->depth;
    //do_delayed_call(&last->done);
    if (!(nd->flags & LOOKUP_RCU))
        path_put(&last->link);
}

static inline int d_revalidate(struct dentry *dentry, unsigned int flags)
{
    if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE))
        return dentry->d_op->d_revalidate(dentry, flags);
    else
        return 1;
}

/**
 * try_to_unlazy - try to switch to ref-walk mode.
 * @nd: nameidata pathwalk data
 * Returns: true on success, false on failure
 *
 * try_to_unlazy attempts to legitimize the current nd->path and nd->root
 * for ref-walk mode.
 * Must be called from rcu-walk context.
 * Nothing should touch nameidata between try_to_unlazy() failure and
 * terminate_walk().
 */
static bool try_to_unlazy(struct nameidata *nd)
{
    struct dentry *parent = nd->path.dentry;

    BUG_ON(!(nd->flags & LOOKUP_RCU));

    nd->flags &= ~LOOKUP_RCU;
#if 0
    if (unlikely(!legitimize_links(nd)))
        goto out1;
    if (unlikely(!legitimize_path(nd, &nd->path, nd->seq)))
        goto out;
    if (unlikely(!legitimize_root(nd)))
        goto out;
#endif
    rcu_read_unlock();
    BUG_ON(nd->inode != parent->d_inode);
    return true;

 out1:
    nd->path.mnt = NULL;
    nd->path.dentry = NULL;

 out:
    rcu_read_unlock();
    return false;
}

static struct dentry *lookup_fast(struct nameidata *nd,
                                  struct inode **inode,
                                  unsigned *seqp)
{
    struct dentry *dentry, *parent = nd->path.dentry;
    int status = 1;

    /*
     * Rename seqlock is not required here because in the off chance
     * of a false negative due to a concurrent rename, the caller is
     * going to fall back to non-racy lookup.
     */
    if (nd->flags & LOOKUP_RCU) {
        unsigned seq;
        dentry = __d_lookup_rcu(parent, &nd->last, &seq);
        if (unlikely(!dentry)) {
            if (!try_to_unlazy(nd))
                return ERR_PTR(-ECHILD);
            return NULL;
        }

        /*
         * This sequence count validates that the inode matches
         * the dentry name information from lookup.
         */
        *inode = d_backing_inode(dentry);
        if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
            return ERR_PTR(-ECHILD);

        /*
         * This sequence count validates that the parent had no
         * changes while we did the lookup of the dentry above.
         *
         * The memory barrier in read_seqcount_begin of child is
         *  enough, we can use __read_seqcount_retry here.
         */
        if (unlikely(__read_seqcount_retry(&parent->d_seq, nd->seq)))
            return ERR_PTR(-ECHILD);

        *seqp = seq;
        status = d_revalidate(dentry, nd->flags);
        if (likely(status > 0))
            return dentry;
#if 0
        if (!try_to_unlazy_next(nd, dentry, seq))
            return ERR_PTR(-ECHILD);
#endif
        if (status == -ECHILD)
            /* we'd been told to redo it in non-rcu mode */
            status = d_revalidate(dentry, nd->flags);
    } else {
        dentry = __d_lookup(parent, &nd->last);
        if (unlikely(!dentry))
            return NULL;
        status = d_revalidate(dentry, nd->flags);
    }
    if (unlikely(status <= 0)) {
        if (!status)
            d_invalidate(dentry);
        dput(dentry);
        return ERR_PTR(status);
    }
    return dentry;
}

/*
 * Try to skip to top of mountpoint pile in rcuwalk mode.  Fail if
 * we meet a managed dentry that would need blocking.
 */
static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
                               struct inode **inode, unsigned *seqp)
{
    struct dentry *dentry = path->dentry;
    unsigned int flags = dentry->d_flags;

    if (likely(!(flags & DCACHE_MANAGED_DENTRY)))
        return true;

    if (unlikely(nd->flags & LOOKUP_NO_XDEV))
        return false;

    for (;;) {
        /*
         * Don't forget we might have a non-mountpoint managed dentry
         * that wants to block transit.
         */
        if (unlikely(flags & DCACHE_MANAGE_TRANSIT)) {
            int res = dentry->d_op->d_manage(path, true);
            if (res)
                return res == -EISDIR;
            flags = dentry->d_flags;
        }

        if (flags & DCACHE_MOUNTED) {
            struct mount *mounted = __lookup_mnt(path->mnt, dentry);
            if (mounted) {
                path->mnt = &mounted->mnt;
                dentry = path->dentry = mounted->mnt.mnt_root;
                nd->state |= ND_JUMPED;
                *seqp = read_seqcount_begin(&dentry->d_seq);
                *inode = dentry->d_inode;
                /*
                 * We don't need to re-check ->d_seq after this
                 * ->d_inode read - there will be an RCU delay
                 * between mount hash removal and ->mnt_root
                 * becoming unpinned.
                 */
                flags = dentry->d_flags;
                continue;
            }
            if (read_seqretry(&mount_lock, nd->m_seq))
                return false;
        }
        return !(flags & DCACHE_NEED_AUTOMOUNT);
    }
}

/*
 * mount traversal - out-of-line part.  One note on ->d_flags accesses -
 * dentries are pinned but not locked here, so negative dentry can go
 * positive right under us.  Use of smp_load_acquire() provides a barrier
 * sufficient for ->d_inode and ->d_flags consistency.
 */
static int __traverse_mounts(struct path *path, unsigned flags,
                             bool *jumped, int *count,
                             unsigned lookup_flags)
{
    struct vfsmount *mnt = path->mnt;
    bool need_mntput = false;
    int ret = 0;

    while (flags & DCACHE_MANAGED_DENTRY) {
        /* Allow the filesystem to manage the transit without i_mutex
         * being held. */
        if (flags & DCACHE_MANAGE_TRANSIT) {
            ret = path->dentry->d_op->d_manage(path, false);
            flags = smp_load_acquire(&path->dentry->d_flags);
            if (ret < 0)
                break;
        }

        if (flags & DCACHE_MOUNTED) {   // something's mounted on it..
            struct vfsmount *mounted = lookup_mnt(path);
            if (mounted) {      // ... in our namespace
                dput(path->dentry);
                if (need_mntput)
                    mntput(path->mnt);
                path->mnt = mounted;
                path->dentry = dget(mounted->mnt_root);
                // here we know it's positive
                flags = path->dentry->d_flags;
                need_mntput = true;
                continue;
            }
        }

        panic("%s: 1!\n", __func__);
    }

    if (ret == -EISDIR)
        ret = 0;
    // possible if you race with several mount --move
    if (need_mntput && path->mnt == mnt)
        mntput(path->mnt);
    if (!ret && unlikely(d_flags_negative(flags)))
        ret = -ENOENT;
    *jumped = need_mntput;
    return ret;
}

static inline int traverse_mounts(struct path *path, bool *jumped,
                                  int *count, unsigned lookup_flags)
{
    unsigned flags = smp_load_acquire(&path->dentry->d_flags);

    /* fastpath */
    if (likely(!(flags & DCACHE_MANAGED_DENTRY))) {
        *jumped = false;
        if (unlikely(d_flags_negative(flags)))
            return -ENOENT;
        return 0;
    }
    return __traverse_mounts(path, flags, jumped, count, lookup_flags);
}

static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
                                struct path *path, struct inode **inode,
                                unsigned int *seqp)
{
    bool jumped;
    int ret;

    path->mnt = nd->path.mnt;
    path->dentry = dentry;
    if (nd->flags & LOOKUP_RCU) {
        unsigned int seq = *seqp;
        if (unlikely(!*inode))
            return -ENOENT;
        if (likely(__follow_mount_rcu(nd, path, inode, seqp)))
            return 0;
#if 0
        if (!try_to_unlazy_next(nd, dentry, seq))
            return -ECHILD;
#endif
        // *path might've been clobbered by __follow_mount_rcu()
        path->mnt = nd->path.mnt;
        path->dentry = dentry;
    }

    ret = traverse_mounts(path, &jumped, &nd->total_link_count, nd->flags);
    if (jumped) {
        if (unlikely(nd->flags & LOOKUP_NO_XDEV))
            ret = -EXDEV;
        else
            nd->state |= ND_JUMPED;
    }

    if (unlikely(ret)) {
        dput(path->dentry);
        if (path->mnt != nd->path.mnt)
            mntput(path->mnt);
    } else {
        *inode = d_backing_inode(path->dentry);
        *seqp = 0; /* out of RCU mode, so the value doesn't matter */
    }
    return ret;
}

/*
 * Do we need to follow links? We _really_ want to be able
 * to do this check without having to look at inode->i_op,
 * so we keep a cache of "no, this doesn't need follow_link"
 * for the common case.
 */
static const char *
step_into(struct nameidata *nd, int flags, struct dentry *dentry,
          struct inode *inode, unsigned seq)
{
    struct path path;
    int err = handle_mounts(nd, dentry, &path, &inode, &seq);
    if (err < 0)
        return ERR_PTR(err);
    if (likely(!d_is_symlink(path.dentry)) ||
       ((flags & WALK_TRAILING) && !(nd->flags & LOOKUP_FOLLOW)) ||
       (flags & WALK_NOFOLLOW)) {
        /* not a symlink or should not follow */
        if (!(nd->flags & LOOKUP_RCU)) {
            dput(nd->path.dentry);
            if (nd->path.mnt != path.mnt)
                mntput(nd->path.mnt);
        }
        nd->path = path;
        nd->inode = inode;
        nd->seq = seq;
        return NULL;
    }

    panic("%s: [%s] END!\n", __func__, nd->name->name);
}

/* Fast lookup failed, do it the slow way */
static struct dentry *__lookup_slow(const struct qstr *name,
                                    struct dentry *dir,
                                    unsigned int flags)
{
    struct dentry *dentry, *old;
    struct inode *inode = dir->d_inode;
    DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

    /* Don't go there if it's already dead */
    if (unlikely(IS_DEADDIR(inode)))
        return ERR_PTR(-ENOENT);

again:
    dentry = d_alloc_parallel(dir, name, &wq);
    if (IS_ERR(dentry))
        return dentry;
    if (unlikely(!d_in_lookup(dentry))) {
        int error = d_revalidate(dentry, flags);
        if (unlikely(error <= 0)) {
            if (!error) {
                d_invalidate(dentry);
                dput(dentry);
                goto again;
            }
            dput(dentry);
            dentry = ERR_PTR(error);
        }
    } else {
        old = inode->i_op->lookup(inode, dentry, flags);
        d_lookup_done(dentry);
        if (unlikely(old)) {
            dput(dentry);
            dentry = old;
        }
    }
    return dentry;
}

static struct dentry *lookup_slow(const struct qstr *name,
                                  struct dentry *dir,
                                  unsigned int flags)
{
    struct inode *inode = dir->d_inode;
    struct dentry *res;
    inode_lock_shared(inode);
    res = __lookup_slow(name, dir, flags);
    inode_unlock_shared(inode);
    return res;
}

static const char *walk_component(struct nameidata *nd, int flags)
{
    struct dentry *dentry;
    struct inode *inode;
    unsigned seq;

    /*
     * "." and ".." are special - ".." especially so because it has
     * to be able to know about the current root directory and
     * parent relationships.
     */
    if (unlikely(nd->last_type != LAST_NORM)) {
        if (!(flags & WALK_MORE) && nd->depth)
            put_link(nd);
        return handle_dots(nd, nd->last_type);
    }

    dentry = lookup_fast(nd, &inode, &seq);
    if (IS_ERR(dentry))
        return ERR_CAST(dentry);
    if (unlikely(!dentry)) {
        dentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);
        if (IS_ERR(dentry))
            return ERR_CAST(dentry);
    }
    if (!(flags & WALK_MORE) && nd->depth)
        put_link(nd);
    return step_into(nd, flags, dentry, inode, seq);
}

/*
 * Name resolution.
 * This is the basic name resolution function, turning a pathname into
 * the final dentry. We expect 'base' to be positive and a directory.
 *
 * Returns 0 and nd will have valid dentry and mnt on success.
 * Returns error and drops reference to input namei data on failure.
 */
static int link_path_walk(const char *name, struct nameidata *nd)
{
    int depth = 0; // depth <= nd->depth
    int err;

    nd->last_type = LAST_ROOT;
    nd->flags |= LOOKUP_PARENT;
    if (IS_ERR(name))
        return PTR_ERR(name);

    while (*name=='/')
        name++;
    if (!*name) {
        nd->dir_mode = 0; // short-circuit the 'hardening' idiocy
        return 0;
    }

    /* At this point we know we have a real path component. */
    for(;;) {
        //struct user_namespace *mnt_userns;
        const char *link;
        u64 hash_len;
        int type;

#if 0
        mnt_userns = mnt_user_ns(nd->path.mnt);
        err = may_lookup(mnt_userns, nd);
        if (err)
            return err;
#endif

        hash_len = hash_name(nd->path.dentry, name);

        type = LAST_NORM;
        if (name[0] == '.') switch (hashlen_len(hash_len)) {
            case 2:
                if (name[1] == '.') {
                    type = LAST_DOTDOT;
                    nd->state |= ND_JUMPED;
                }
                break;
            case 1:
                type = LAST_DOT;
        }
        if (likely(type == LAST_NORM)) {
            struct dentry *parent = nd->path.dentry;
            nd->state &= ~ND_JUMPED;
            if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
                struct qstr this = { { .hash_len = hash_len }, .name = name };
                err = parent->d_op->d_hash(parent, &this);
                if (err < 0)
                    return err;
                hash_len = this.hash_len;
                name = this.name;
            }
        }

        nd->last.hash_len = hash_len;
        nd->last.name = name;
        nd->last_type = type;

        name += hashlen_len(hash_len);
        if (!*name)
            goto OK;
        /*
         * If it wasn't NUL, we know it was '/'. Skip that
         * slash, and continue until no more slashes.
         */
        do {
            name++;
        } while (unlikely(*name == '/'));
        if (unlikely(!*name)) {
OK:
            /* pathname or trailing symlink, done */
            if (!depth) {
                //nd->dir_uid = i_uid_into_mnt(mnt_userns, nd->inode);
                nd->dir_mode = nd->inode->i_mode;
                nd->flags &= ~LOOKUP_PARENT;
                return 0;
            }
            /* last component of nested symlink */
            name = nd->stack[--depth].name;
            link = walk_component(nd, 0);
        } else {
            /* not the last component */
            link = walk_component(nd, WALK_MORE);
        }
        if (unlikely(link)) {
            if (IS_ERR(link))
                return PTR_ERR(link);
            /* a symlink to follow */
            nd->stack[depth++].name = name;
            name = link;
            continue;
        }

        if (unlikely(!d_can_lookup(nd->path.dentry))) {
            if (nd->flags & LOOKUP_RCU) {
#if 0
                if (!try_to_unlazy(nd))
                    return -ECHILD;
#endif
            }
            return -ENOTDIR;
        }
    }

    panic("%s: [%s] END!\n", __func__, name);
}

/**
 * complete_walk - successful completion of path walk
 * @nd:  pointer nameidata
 *
 * If we had been in RCU mode, drop out of it and legitimize nd->path.
 * Revalidate the final result, unless we'd already done that during
 * the path walk or the filesystem doesn't ask for it.  Return 0 on
 * success, -error on failure.  In case of failure caller does not
 * need to drop nd->path.
 */
static int complete_walk(struct nameidata *nd)
{
    struct dentry *dentry = nd->path.dentry;
    int status;

    if (nd->flags & LOOKUP_RCU) {
        /*
         * We don't want to zero nd->root for scoped-lookups or
         * externally-managed nd->root.
         */
        if (!(nd->state & ND_ROOT_PRESET))
            if (!(nd->flags & LOOKUP_IS_SCOPED))
                nd->root.mnt = NULL;
        nd->flags &= ~LOOKUP_CACHED;
#if 0
        if (!try_to_unlazy(nd))
            return -ECHILD;
#endif
    }

    if (unlikely(nd->flags & LOOKUP_IS_SCOPED)) {
        /*
         * While the guarantee of LOOKUP_IS_SCOPED is (roughly) "don't
         * ever step outside the root during lookup" and should already
         * be guaranteed by the rest of namei, we want to avoid a namei
         * BUG resulting in userspace being given a path that was not
         * scoped within the root at some point during the lookup.
         *
         * So, do a final sanity-check to make sure that in the
         * worst-case scenario (a complete bypass of LOOKUP_IS_SCOPED)
         * we won't silently return an fd completely outside of the
         * requested root to userspace.
         *
         * Userspace could move the path outside the root after this
         * check, but as discussed elsewhere this is not a concern (the
         * resolved file was inside the root at some point).
         */
        if (!path_is_under(&nd->path, &nd->root))
            return -EXDEV;
    }

    if (likely(!(nd->state & ND_JUMPED)))
        return 0;

    if (likely(!(dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE)))
        return 0;

    status = dentry->d_op->d_weak_revalidate(dentry, nd->flags);
    if (status > 0)
        return 0;

    if (!status)
        status = -ESTALE;

    panic("%s: [%s] END!\n", __func__, nd->name->name);
    return status;
}

static void drop_links(struct nameidata *nd)
{
    int i = nd->depth;
    while (i--) {
        struct saved *last = nd->stack + i;
#if 0
        do_delayed_call(&last->done);
        clear_delayed_call(&last->done);
#endif
        panic("%s: END!\n", __func__);
    }
}

static void terminate_walk(struct nameidata *nd)
{
    drop_links(nd);
    if (!(nd->flags & LOOKUP_RCU)) {
        int i;
        path_put(&nd->path);
        for (i = 0; i < nd->depth; i++)
            path_put(&nd->stack[i].link);
        if (nd->state & ND_ROOT_GRABBED) {
            path_put(&nd->root);
            nd->state &= ~ND_ROOT_GRABBED;
        }
    } else {
        nd->flags &= ~LOOKUP_RCU;
        rcu_read_unlock();
    }
    nd->depth = 0;
    nd->path.mnt = NULL;
    nd->path.dentry = NULL;
}

/* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
static int path_parentat(struct nameidata *nd, unsigned flags,
                         struct path *parent)
{
    const char *s = path_init(nd, flags);
    int err = link_path_walk(s, nd);
    if (!err)
        err = complete_walk(nd);
    if (!err) {
        *parent = nd->path;
        nd->path.mnt = NULL;
        nd->path.dentry = NULL;
    }
    terminate_walk(nd);
    return err;
}

static void restore_nameidata(void)
{
    struct nameidata *now = current->nameidata, *old = now->saved;

    current->nameidata = old;
    if (old)
        old->total_link_count = now->total_link_count;
    if (now->stack != now->internal)
        kfree(now->stack);
}

/* Note: this does not consume "name" */
static int filename_parentat(int dfd, struct filename *name,
                             unsigned int flags, struct path *parent,
                             struct qstr *last, int *type)
{
    int retval;
    struct nameidata nd;

    if (IS_ERR(name))
        return PTR_ERR(name);
    set_nameidata(&nd, dfd, name, NULL);
    retval = path_parentat(&nd, flags | LOOKUP_RCU, parent);
    if (unlikely(retval == -ECHILD))
        retval = path_parentat(&nd, flags, parent);
    if (unlikely(retval == -ESTALE))
        retval = path_parentat(&nd, flags | LOOKUP_REVAL, parent);
    if (likely(!retval)) {
        *last = nd.last;
        *type = nd.last_type;
    }
    restore_nameidata();
    return retval;
}

/*
 * This looks up the name in dcache and possibly revalidates the found dentry.
 * NULL is returned if the dentry does not exist in the cache.
 */
static struct dentry *lookup_dcache(const struct qstr *name,
                                    struct dentry *dir,
                                    unsigned int flags)
{
    struct dentry *dentry = d_lookup(dir, name);
    if (dentry) {
        int error = d_revalidate(dentry, flags);
        if (unlikely(error <= 0)) {
            if (!error)
                d_invalidate(dentry);
            dput(dentry);
            return ERR_PTR(error);
        }
    }
    return dentry;
}

/*
 * Parent directory has inode locked exclusive.  This is one
 * and only case when ->lookup() gets called on non in-lookup
 * dentries - as the matter of fact, this only gets called
 * when directory is guaranteed to have no in-lookup children
 * at all.
 */
static struct dentry *__lookup_hash(const struct qstr *name,
                                    struct dentry *base, unsigned int flags)
{
    struct dentry *dentry = lookup_dcache(name, base, flags);
    struct dentry *old;
    struct inode *dir = base->d_inode;

    if (dentry)
        return dentry;

    /* Don't create child dentry for a dead directory. */
    if (unlikely(IS_DEADDIR(dir)))
        return ERR_PTR(-ENOENT);

    dentry = d_alloc(base, name);
    if (unlikely(!dentry))
        return ERR_PTR(-ENOMEM);

    old = dir->i_op->lookup(dir, dentry, flags);
    if (unlikely(old)) {
        dput(dentry);
        dentry = old;
    }
    return dentry;
}

static struct dentry *
filename_create(int dfd, struct filename *name,
                struct path *path, unsigned int lookup_flags)
{
    struct dentry *dentry = ERR_PTR(-EEXIST);
    struct qstr last;
    bool want_dir = lookup_flags & LOOKUP_DIRECTORY;
    unsigned int reval_flag = lookup_flags & LOOKUP_REVAL;
    unsigned int create_flags = LOOKUP_CREATE | LOOKUP_EXCL;
    int type;
    int err2;
    int error;

    error = filename_parentat(dfd, name, reval_flag, path, &last, &type);
    if (error)
        return ERR_PTR(error);

    /*
     * Yucky last component or no last component at all?
     * (foo/., foo/.., /////)
     */
    if (unlikely(type != LAST_NORM))
        goto out;

#if 0
    /* don't fail immediately if it's r/o, at least try to report other errors */
    err2 = mnt_want_write(path->mnt);
#endif
    /*
     * Do the final lookup.  Suppress 'create' if there is a trailing
     * '/', and a directory wasn't requested.
     */
    if (last.name[last.len] && !want_dir)
        create_flags = 0;
    inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);
    dentry = __lookup_hash(&last, path->dentry, reval_flag | create_flags);
    if (IS_ERR(dentry))
        goto unlock;

    error = -EEXIST;
    if (d_is_positive(dentry))
        goto fail;

    /*
     * Special case - lookup gave negative, but... we had foo/bar/
     * From the vfs_mknod() POV we just have a negative dentry -
     * all is fine. Let's be bastards - you had / on the end, you've
     * been asking for (non-existent) directory. -ENOENT for you.
     */
    if (unlikely(!create_flags)) {
        error = -ENOENT;
        goto fail;
    }
    if (unlikely(err2)) {
        error = err2;
        goto fail;
    }

    return dentry;

 fail:
    dput(dentry);
    dentry = ERR_PTR(error);
 unlock:
    inode_unlock(path->dentry->d_inode);
    if (!err2)
        mnt_drop_write(path->mnt);
 out:
    path_put(path);
    return dentry;
}

struct dentry *kern_path_create(int dfd, const char *pathname,
                                struct path *path, unsigned int lookup_flags)
{
    struct filename *filename = getname_kernel(pathname);
    struct dentry *res = filename_create(dfd, filename, path, lookup_flags);

    putname(filename);
    return res;
}
EXPORT_SYMBOL(kern_path_create);

/**
 * vfs_mkdir - create directory
 * @mnt_userns: user namespace of the mount the inode was found from
 * @dir:    inode of @dentry
 * @dentry: pointer to dentry of the base directory
 * @mode:   mode of the new directory
 *
 * Create a directory.
 *
 * If the inode has been found through an idmapped mount the user namespace of
 * the vfsmount must be passed through @mnt_userns. This function will then take
 * care to map the inode according to @mnt_userns before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply passs init_user_ns.
 */
int vfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
              struct dentry *dentry, umode_t mode)
{
#if 0
    int error = may_create(mnt_userns, dir, dentry);
#else
    int error;
#endif
    unsigned max_links = dir->i_sb->s_max_links;

#if 0
    if (error)
        return error;
#endif

    if (!dir->i_op->mkdir)
        return -EPERM;

    mode &= (S_IRWXUGO|S_ISVTX);

    if (max_links && dir->i_nlink >= max_links)
        return -EMLINK;

    error = dir->i_op->mkdir(mnt_userns, dir, dentry, mode);
#if 0
    if (!error)
        fsnotify_mkdir(dir, dentry);
#endif
    return error;
}
EXPORT_SYMBOL(vfs_mkdir);

void done_path_create(struct path *path, struct dentry *dentry)
{
    dput(dentry);
    inode_unlock(path->dentry->d_inode);
    mnt_drop_write(path->mnt);
    path_put(path);
}
EXPORT_SYMBOL(done_path_create);

/**
 * vfs_mknod - create device node or file
 * @mnt_userns: user namespace of the mount the inode was found from
 * @dir:    inode of @dentry
 * @dentry: pointer to dentry of the base directory
 * @mode:   mode of the new device node or file
 * @dev:    device number of device to create
 *
 * Create a device node or file.
 *
 * If the inode has been found through an idmapped mount the user namespace of
 * the vfsmount must be passed through @mnt_userns. This function will then take
 * care to map the inode according to @mnt_userns before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply passs init_user_ns.
 */
int vfs_mknod(struct user_namespace *mnt_userns, struct inode *dir,
              struct dentry *dentry, umode_t mode, dev_t dev)
{
#if 0
    bool is_whiteout = S_ISCHR(mode) && dev == WHITEOUT_DEV;
    int error = may_create(mnt_userns, dir, dentry);

    if (error)
        return error;
#else
    int error;
#endif

    if (!dir->i_op->mknod)
        return -EPERM;

#if 0
    error = devcgroup_inode_mknod(mode, dev);
    if (error)
        return error;
#endif

    error = dir->i_op->mknod(mnt_userns, dir, dentry, mode, dev);
#if 0
    if (!error)
        fsnotify_create(dir, dentry);
#endif
    return error;
}
EXPORT_SYMBOL(vfs_mknod);

static inline const char *lookup_last(struct nameidata *nd)
{
    if (nd->last_type == LAST_NORM && nd->last.name[nd->last.len])
        nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

    return walk_component(nd, WALK_TRAILING);
}

static int handle_lookup_down(struct nameidata *nd)
{
    if (!(nd->flags & LOOKUP_RCU))
        dget(nd->path.dentry);
    return PTR_ERR(step_into(nd, WALK_NOFOLLOW,
                             nd->path.dentry, nd->inode, nd->seq));
}

/* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
static int path_lookupat(struct nameidata *nd, unsigned flags,
                         struct path *path)
{
    const char *s = path_init(nd, flags);
    int err;

    if (unlikely(flags & LOOKUP_DOWN) && !IS_ERR(s)) {
        err = handle_lookup_down(nd);
        if (unlikely(err < 0))
            s = ERR_PTR(err);
    }

    while (!(err = link_path_walk(s, nd)) &&
           (s = lookup_last(nd)) != NULL)
        ;
    if (!err && unlikely(nd->flags & LOOKUP_MOUNTPOINT)) {
        err = handle_lookup_down(nd);
        nd->state &= ~ND_JUMPED; // no d_weak_revalidate(), please...
    }
    if (!err)
        err = complete_walk(nd);

    if (!err && nd->flags & LOOKUP_DIRECTORY)
        if (!d_can_lookup(nd->path.dentry))
            err = -ENOTDIR;
    if (!err) {
        *path = nd->path;
        nd->path.mnt = NULL;
        nd->path.dentry = NULL;
    }
    terminate_walk(nd);
    return err;
}

int filename_lookup(int dfd, struct filename *name, unsigned flags,
                    struct path *path, struct path *root)
{
    int retval;
    struct nameidata nd;
    if (IS_ERR(name))
        return PTR_ERR(name);
    set_nameidata(&nd, dfd, name, root);
    retval = path_lookupat(&nd, flags | LOOKUP_RCU, path);
    if (unlikely(retval == -ECHILD))
        retval = path_lookupat(&nd, flags, path);
    if (unlikely(retval == -ESTALE))
        retval = path_lookupat(&nd, flags | LOOKUP_REVAL, path);

    restore_nameidata();
    return retval;
}

int kern_path(const char *name, unsigned int flags, struct path *path)
{
    struct filename *filename = getname_kernel(name);
    int ret = filename_lookup(AT_FDCWD, filename, flags, path, NULL);

    putname(filename);
    return ret;

}
EXPORT_SYMBOL(kern_path);

/**
 * sb_permission - Check superblock-level permissions
 * @sb: Superblock of inode to check permission on
 * @inode: Inode to check permission on
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Separate out file-system wide checks from inode-specific permission checks.
 */
static int sb_permission(struct super_block *sb, struct inode *inode, int mask)
{
    if (unlikely(mask & MAY_WRITE)) {
        umode_t mode = inode->i_mode;

        /* Nobody gets write access to a read-only fs. */
        if (sb_rdonly(sb) && (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
            return -EROFS;
    }
    return 0;
}

/**
 * generic_permission -  check for access rights on a Posix-like filesystem
 * @mnt_userns: user namespace of the mount the inode was found from
 * @inode:  inode to check access rights for
 * @mask:   right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC,
 *      %MAY_NOT_BLOCK ...)
 *
 * Used to check for read/write/execute permissions on a file.
 * We use "fsuid" for this, letting us set arbitrary permissions
 * for filesystem access without changing the "normal" uids which
 * are used for other things.
 *
 * generic_permission is rcu-walk aware. It returns -ECHILD in case an rcu-walk
 * request cannot be satisfied (eg. requires blocking or too much complexity).
 * It would then be called again in ref-walk mode.
 *
 * If the inode has been found through an idmapped mount the user namespace of
 * the vfsmount must be passed through @mnt_userns. This function will then take
 * care to map the inode according to @mnt_userns before checking permissions.
 * On non-idmapped mounts or if permission checking is to be performed on the
 * raw inode simply passs init_user_ns.
 */
int generic_permission(struct user_namespace *mnt_userns, struct inode *inode,
                       int mask)
{
    pr_warn("%s: no implementation!\n", __func__);
    return 0;
}

/**
 * do_inode_permission - UNIX permission checking
 * @mnt_userns: user namespace of the mount the inode was found from
 * @inode:  inode to check permissions on
 * @mask:   right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC ...)
 *
 * We _really_ want to just do "generic_permission()" without
 * even looking at the inode->i_op values. So we keep a cache
 * flag in inode->i_opflags, that says "this has not special
 * permission function, use the fast case".
 */
static inline int do_inode_permission(struct user_namespace *mnt_userns,
                                      struct inode *inode, int mask)
{
    if (unlikely(!(inode->i_opflags & IOP_FASTPERM))) {
        if (likely(inode->i_op->permission))
            return inode->i_op->permission(mnt_userns, inode, mask);

        /* This gets set once for the inode lifetime */
        spin_lock(&inode->i_lock);
        inode->i_opflags |= IOP_FASTPERM;
        spin_unlock(&inode->i_lock);
    }
    return generic_permission(mnt_userns, inode, mask);
}

/**
 * inode_permission - Check for access rights to a given inode
 * @mnt_userns: User namespace of the mount the inode was found from
 * @inode:  Inode to check permission on
 * @mask:   Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Check for read/write/execute permissions on an inode.  We use fs[ug]id for
 * this, letting us set arbitrary permissions for filesystem access without
 * changing the "normal" UIDs which are used for other things.
 *
 * When checking for MAY_APPEND, MAY_WRITE must also be set in @mask.
 */
int inode_permission(struct user_namespace *mnt_userns,
                     struct inode *inode, int mask)
{
    int retval;

    retval = sb_permission(inode->i_sb, inode, mask);
    if (retval)
        return retval;

    if (unlikely(mask & MAY_WRITE)) {
        panic("%s: MAY_WRITE!\n", __func__);
    }

    retval = do_inode_permission(mnt_userns, inode, mask);
    if (retval)
        return retval;

#if 0
    retval = devcgroup_inode_permission(inode, mask);
    if (retval)
        return retval;
#endif

    return 0;
}
EXPORT_SYMBOL(inode_permission);

/*
 * Make sure that the actual truncation of the file will occur outside its
 * directory's i_mutex.  Truncate can take a long time if there is a lot of
 * writeout happening, and we don't want to prevent access to the directory
 * while waiting on the I/O.
 */
int do_unlinkat(int dfd, struct filename *name)
{
#if 0
    int error;
    struct dentry *dentry;
    struct path path;
    struct qstr last;
    int type;
    struct inode *inode = NULL;
    struct inode *delegated_inode = NULL;
    unsigned int lookup_flags = 0;

 retry:
    error = filename_parentat(dfd, name, lookup_flags, &path, &last, &type);
    if (error)
        goto exit1;

    error = -EISDIR;
    if (type != LAST_NORM)
        goto exit2;

    error = mnt_want_write(path.mnt);
    if (error)
        goto exit2;

    panic("%s: name(%s) NO do_unlinkat!\n", __func__, name->name);

 exit2:
    path_put(&path);
    if (retry_estale(error, lookup_flags)) {
        lookup_flags |= LOOKUP_REVAL;
        inode = NULL;
        goto retry;
    }
 exit1:
    putname(name);
    return error;
#else
    pr_warn("%s: no implementation!\n", __func__);
    return 0;
#endif
}

bool may_open_dev(const struct path *path)
{
    return !(path->mnt->mnt_flags & MNT_NODEV) &&
        !(path->mnt->mnt_sb->s_iflags & SB_I_NODEV);
}

static int may_o_create(struct user_namespace *mnt_userns,
                        const struct path *dir, struct dentry *dentry,
                        umode_t mode)
{
    int error;

#if 0
    if (!fsuidgid_has_mapping(dir->dentry->d_sb, mnt_userns))
        return -EOVERFLOW;
#endif

    error = inode_permission(mnt_userns, dir->dentry->d_inode,
                             MAY_WRITE | MAY_EXEC);
    if (error)
        return error;

    return 0;
}

/*
 * Look up and maybe create and open the last component.
 *
 * Must be called with parent locked (exclusive in O_CREAT case).
 *
 * Returns 0 on success, that is, if
 *  the file was successfully atomically created (if necessary) and opened, or
 *  the file was not completely opened at this time, though lookups and
 *  creations were performed.
 * These case are distinguished by presence of FMODE_OPENED on file->f_mode.
 * In the latter case dentry returned in @path might be negative if O_CREAT
 * hadn't been specified.
 *
 * An error code is returned on failure.
 */
static struct dentry *lookup_open(struct nameidata *nd, struct file *file,
                                  const struct open_flags *op,
                                  bool got_write)
{
    struct user_namespace *mnt_userns;
    struct dentry *dir = nd->path.dentry;
    struct inode *dir_inode = dir->d_inode;
    int open_flag = op->open_flag;
    struct dentry *dentry;
    int error, create_error = 0;
    umode_t mode = op->mode;
    DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

    if (unlikely(IS_DEADDIR(dir_inode)))
        return ERR_PTR(-ENOENT);

    file->f_mode &= ~FMODE_CREATED;
    dentry = d_lookup(dir, &nd->last);
    for (;;) {
        if (!dentry) {
            dentry = d_alloc_parallel(dir, &nd->last, &wq);
            if (IS_ERR(dentry))
                return dentry;
        }
        if (d_in_lookup(dentry))
            break;

        error = d_revalidate(dentry, nd->flags);
        if (likely(error > 0))
            break;
        if (error)
            goto out_dput;
        d_invalidate(dentry);
        dput(dentry);
        dentry = NULL;
    }
    if (dentry->d_inode) {
        /* Cached positive dentry: will open in f_op->open */
        return dentry;
    }

    /*
     * Checking write permission is tricky, bacuse we don't know if we are
     * going to actually need it: O_CREAT opens should work as long as the
     * file exists.  But checking existence breaks atomicity.  The trick is
     * to check access and if not granted clear O_CREAT from the flags.
     *
     * Another problem is returing the "right" error value (e.g. for an
     * O_EXCL open we want to return EEXIST not EROFS).
     */
    if (unlikely(!got_write))
        open_flag &= ~O_TRUNC;
    mnt_userns = mnt_user_ns(nd->path.mnt);
    if (open_flag & O_CREAT) {
        if (open_flag & O_EXCL)
            open_flag &= ~O_TRUNC;
        if (!IS_POSIXACL(dir->d_inode))
            mode &= ~current_umask();
        if (likely(got_write))
            create_error = may_o_create(mnt_userns, &nd->path, dentry, mode);
        else
            create_error = -EROFS;
    }
    if (create_error)
        open_flag &= ~O_CREAT;
    if (dir_inode->i_op->atomic_open) {
#if 0
        dentry = atomic_open(nd, dentry, file, open_flag, mode);
        if (unlikely(create_error) && dentry == ERR_PTR(-ENOENT))
            dentry = ERR_PTR(create_error);
        return dentry;
#endif
        panic("%s: atomic_open!\n", __func__);
    }

    if (d_in_lookup(dentry)) {
        struct dentry *res = dir_inode->i_op->lookup(dir_inode, dentry,
                                                     nd->flags);
        d_lookup_done(dentry);
        if (unlikely(res)) {
            if (IS_ERR(res)) {
                error = PTR_ERR(res);
                goto out_dput;
            }
            dput(dentry);
            dentry = res;
        }
    }

    /* Negative dentry, just create the file */
    if (!dentry->d_inode && (open_flag & O_CREAT)) {
        file->f_mode |= FMODE_CREATED;
        if (!dir_inode->i_op->create) {
            error = -EACCES;
            goto out_dput;
        }

        error = dir_inode->i_op->create(mnt_userns, dir_inode, dentry,
                                        mode, open_flag & O_EXCL);
        if (error)
            goto out_dput;
    }
    if (unlikely(create_error) && !dentry->d_inode) {
        error = create_error;
        goto out_dput;
    }
    return dentry;

 out_dput:
    dput(dentry);
    return ERR_PTR(error);
}

static const char *
open_last_lookups(struct nameidata *nd,
                  struct file *file,
                  const struct open_flags *op)
{
    struct dentry *dir = nd->path.dentry;
    int open_flag = op->open_flag;
    bool got_write = false;
    unsigned seq;
    struct inode *inode;
    struct dentry *dentry;
    const char *res;

    nd->flags |= op->intent;

    if (nd->last_type != LAST_NORM) {
        if (nd->depth)
            put_link(nd);
        return handle_dots(nd, nd->last_type);
    }

    if (!(open_flag & O_CREAT)) {
        if (nd->last.name[nd->last.len])
            nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
        /* we _can_ be in RCU mode here */
        dentry = lookup_fast(nd, &inode, &seq);
        if (IS_ERR(dentry))
            return ERR_CAST(dentry);
        if (likely(dentry))
            goto finish_lookup;

        BUG_ON(nd->flags & LOOKUP_RCU);
    } else {
#if 0
        /* create side of things */
        if (nd->flags & LOOKUP_RCU) {
            if (!try_to_unlazy(nd))
                return ERR_PTR(-ECHILD);
        }
        audit_inode(nd->name, dir, AUDIT_INODE_PARENT);
        /* trailing slashes? */
        if (unlikely(nd->last.name[nd->last.len]))
            return ERR_PTR(-EISDIR);
#endif
        panic("%s: O_CREAT!\n", __func__);
    }

    if (open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) {
        got_write = !mnt_want_write(nd->path.mnt);
        /*
         * do _not_ fail yet - we might not need that or fail with
         * a different error; let lookup_open() decide; we'll be
         * dropping this one anyway.
         */
    }
    if (open_flag & O_CREAT)
        inode_lock(dir->d_inode);
    else
        inode_lock_shared(dir->d_inode);
    dentry = lookup_open(nd, file, op, got_write);
#if 0
    if (!IS_ERR(dentry) && (file->f_mode & FMODE_CREATED))
        fsnotify_create(dir->d_inode, dentry);
#endif
    if (open_flag & O_CREAT)
        inode_unlock(dir->d_inode);
    else
        inode_unlock_shared(dir->d_inode);

    if (got_write)
        mnt_drop_write(nd->path.mnt);

    if (IS_ERR(dentry))
        return ERR_CAST(dentry);

    if (file->f_mode & (FMODE_OPENED | FMODE_CREATED)) {
        dput(nd->path.dentry);
        nd->path.dentry = dentry;
        return NULL;
    }

 finish_lookup:
    if (nd->depth)
        put_link(nd);
    res = step_into(nd, WALK_TRAILING, dentry, inode, seq);
    if (unlikely(res))
        nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
    return res;
}

static int may_open(struct user_namespace *mnt_userns, const struct path *path,
                    int acc_mode, int flag)
{
    struct dentry *dentry = path->dentry;
    struct inode *inode = dentry->d_inode;
    int error;

    if (!inode)
        return -ENOENT;

    switch (inode->i_mode & S_IFMT) {
    case S_IFLNK:
        return -ELOOP;
    case S_IFDIR:
        if (acc_mode & MAY_WRITE)
            return -EISDIR;
        if (acc_mode & MAY_EXEC)
            return -EACCES;
        break;
    case S_IFBLK:
    case S_IFCHR:
        if (!may_open_dev(path))
            return -EACCES;
        fallthrough;
    case S_IFIFO:
    case S_IFSOCK:
        if (acc_mode & MAY_EXEC)
            return -EACCES;
        flag &= ~O_TRUNC;
        break;
    case S_IFREG:
        if ((acc_mode & MAY_EXEC) && path_noexec(path))
            return -EACCES;
        break;
    }

    error = inode_permission(mnt_userns, inode, MAY_OPEN | acc_mode);
    if (error)
        return error;

    /*
     * An append-only file must be opened in append mode for writing.
     */
    if (IS_APPEND(inode)) {
        if  ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND))
            return -EPERM;
        if (flag & O_TRUNC)
            return -EPERM;
    }

#if 0
    /* O_NOATIME can only be set by the owner or superuser */
    if (flag & O_NOATIME && !inode_owner_or_capable(mnt_userns, inode))
        return -EPERM;
#endif

    return 0;
}

static int handle_truncate(struct user_namespace *mnt_userns, struct file *filp)
{
    panic("%s: END!\n", __func__);
}

/*
 * Handle the last step of open()
 */
static int do_open(struct nameidata *nd,
                   struct file *file, const struct open_flags *op)
{
    struct user_namespace *mnt_userns;
    int open_flag = op->open_flag;
    bool do_truncate;
    int acc_mode;
    int error;

    if (!(file->f_mode & (FMODE_OPENED | FMODE_CREATED))) {
        error = complete_walk(nd);
        if (error)
            return error;
    }
#if 0
    if (!(file->f_mode & FMODE_CREATED))
        audit_inode(nd->name, nd->path.dentry, 0);
#endif
    mnt_userns = mnt_user_ns(nd->path.mnt);
    if (open_flag & O_CREAT) {
#if 0
        if ((open_flag & O_EXCL) && !(file->f_mode & FMODE_CREATED))
            return -EEXIST;
        if (d_is_dir(nd->path.dentry))
            return -EISDIR;
        error = may_create_in_sticky(mnt_userns, nd,
                                     d_backing_inode(nd->path.dentry));
        if (unlikely(error))
            return error;
#endif
        panic("%s: O_CREAT!\n", __func__);
    }
    if ((nd->flags & LOOKUP_DIRECTORY) && !d_can_lookup(nd->path.dentry))
        return -ENOTDIR;

    do_truncate = false;
    acc_mode = op->acc_mode;
    if (file->f_mode & FMODE_CREATED) {
        /* Don't check for write permission, don't truncate */
        open_flag &= ~O_TRUNC;
        acc_mode = 0;
    } else if (d_is_reg(nd->path.dentry) && open_flag & O_TRUNC) {
        error = mnt_want_write(nd->path.mnt);
        if (error)
            return error;
        do_truncate = true;
    }
    error = may_open(mnt_userns, &nd->path, acc_mode, open_flag);
    if (!error && !(file->f_mode & FMODE_OPENED))
        error = vfs_open(&nd->path, file);
    if (!error && do_truncate)
        error = handle_truncate(mnt_userns, file);
    if (unlikely(error > 0)) {
        WARN_ON(1);
        error = -EINVAL;
    }
    if (do_truncate)
        mnt_drop_write(nd->path.mnt);
    return error;
}

static struct file *path_openat(struct nameidata *nd,
                                const struct open_flags *op, unsigned flags)
{
    struct file *file;
    int error;

    file = alloc_empty_file(op->open_flag, current_cred());
    if (IS_ERR(file))
        return file;

    if (unlikely(file->f_flags & __O_TMPFILE)) {
        //error = do_tmpfile(nd, flags, op, file);
        panic("%s: __O_TMPFILE!\n", __func__);
    } else if (unlikely(file->f_flags & O_PATH)) {
        //error = do_o_path(nd, flags, file);
        panic("%s: O_PATH!\n", __func__);
    } else {
        const char *s = path_init(nd, flags);
        while (!(error = link_path_walk(s, nd)) &&
               (s = open_last_lookups(nd, file, op)) != NULL)
            ;
        if (!error)
            error = do_open(nd, file, op);
        terminate_walk(nd);
    }
    if (likely(!error)) {
        if (likely(file->f_mode & FMODE_OPENED))
            return file;
        WARN_ON(1);
        error = -EINVAL;
    }
    fput(file);
    if (error == -EOPENSTALE) {
        if (flags & LOOKUP_RCU)
            error = -ECHILD;
        else
            error = -ESTALE;
    }
    return ERR_PTR(error);
}

struct file *do_filp_open(int dfd, struct filename *pathname,
                          const struct open_flags *op)
{
    struct nameidata nd;
    int flags = op->lookup_flags;
    struct file *filp;

    set_nameidata(&nd, dfd, pathname, NULL);
    filp = path_openat(&nd, op, flags | LOOKUP_RCU);
    if (unlikely(filp == ERR_PTR(-ECHILD)))
        filp = path_openat(&nd, op, flags);
    if (unlikely(filp == ERR_PTR(-ESTALE)))
        filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
    restore_nameidata();
    return filp;
}

struct filename *
getname_flags(const char __user *filename, int flags, int *empty)
{
    struct filename *result;
    char *kname;
    int len;

#if 0
    result = audit_reusename(filename);
    if (result)
        return result;
#endif

    result = __getname();
    if (unlikely(!result))
        return ERR_PTR(-ENOMEM);

    /*
     * First, try to embed the struct filename inside the names_cache
     * allocation
     */
    kname = (char *)result->iname;
    result->name = kname;

    len = strncpy_from_user(kname, filename, EMBEDDED_NAME_MAX);
    if (unlikely(len < 0)) {
        __putname(result);
        return ERR_PTR(len);
    }

    printk("%s: kname(%s)\n", __func__, kname);

    /*
     * Uh-oh. We have a name that's approaching PATH_MAX. Allocate a
     * separate struct filename so we can dedicate the entire
     * names_cache allocation for the pathname, and re-do the copy from
     * userland.
     */
    if (unlikely(len == EMBEDDED_NAME_MAX)) {
        panic("%s: EMBEDDED_NAME_MAX!\n", __func__);
    }

    result->refcnt = 1;
    /* The empty path is special. */
    if (unlikely(!len)) {
        if (empty)
            *empty = 1;
        if (!(flags & LOOKUP_EMPTY)) {
            putname(result);
            return ERR_PTR(-ENOENT);
        }
    }

    result->uptr = filename;
    result->aname = NULL;
    //audit_getname(result);
    return result;
}

int user_path_at_empty(int dfd, const char __user *name, unsigned flags,
                       struct path *path, int *empty)
{
    struct filename *filename = getname_flags(name, flags, empty);
    int ret = filename_lookup(dfd, filename, flags, path, NULL);

    putname(filename);
    return ret;
}
EXPORT_SYMBOL(user_path_at_empty);

struct filename *
getname(const char __user * filename)
{
    return getname_flags(filename, 0, NULL);
}
