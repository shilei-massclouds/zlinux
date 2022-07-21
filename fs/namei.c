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
#include <linux/file.h>
#endif
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

#if 0
        do {
            seq = read_seqcount_begin(&fs->seq);
            nd->root = fs->root;
            nd->root_seq = __read_seqcount_begin(&nd->root.dentry->d_seq);
        } while (read_seqcount_retry(&fs->seq, seq));
#else
        nd->root = fs->root;
#endif
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
#if 0
        nd->seq = nd->root_seq;
        if (unlikely(read_seqcount_retry(&d->d_seq, nd->seq)))
            return -ECHILD;
#endif
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

#if 0
    nd->m_seq = __read_seqcount_begin(&mount_lock.seqcount);
    nd->r_seq = __read_seqcount_begin(&rename_lock.seqcount);
#endif
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

    panic("%s: [%s] END!\n", __func__, s);
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

static const char *walk_component(struct nameidata *nd, int flags)
{
    struct dentry *dentry;
    struct inode *inode;
    unsigned seq;

    panic("%s: [%s] END!\n", __func__, nd->name->name);
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

        panic("%s: [%s] in loop!\n", __func__, name);
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

static inline int d_revalidate(struct dentry *dentry, unsigned int flags)
{
    if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE))
        return dentry->d_op->d_revalidate(dentry, flags);
    else
        return 1;
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

    panic("%s: END!\n", __func__);
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
