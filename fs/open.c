// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/open.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
//#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#if 0
#include <linux/capability.h>
#include <linux/security.h>
#endif
#include <linux/securebits.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
//#include <linux/personality.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#if 0
#include <linux/audit.h>
#include <linux/falloc.h>
#include <linux/ima.h>
#include <linux/dnotify.h>
#endif
#include <linux/fs_struct.h>
#include <linux/compat.h>
#include <linux/mnt_idmapping.h>

#include "internal.h"

/*
 * Called when an inode is about to be open.
 * We use this to disallow opening large files on 32bit systems if
 * the caller didn't specify O_LARGEFILE.  On 64bit systems we force
 * on this flag in sys_open.
 */
int generic_file_open(struct inode *inode, struct file *filp)
{
    if (!(filp->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
        return -EOVERFLOW;
    return 0;
}
EXPORT_SYMBOL(generic_file_open);

static int do_dentry_open(struct file *f,
                          struct inode *inode,
                          int (*open)(struct inode *, struct file *))
{
    static const struct file_operations empty_fops = {};
    int error;

    path_get(&f->f_path);
    f->f_inode = inode;
    f->f_mapping = inode->i_mapping;
#if 0
    f->f_wb_err = filemap_sample_wb_err(f->f_mapping);
    f->f_sb_err = file_sample_sb_err(f);
#endif

    if (unlikely(f->f_flags & O_PATH)) {
        f->f_mode = FMODE_PATH | FMODE_OPENED;
        f->f_op = &empty_fops;
        return 0;
    }

    if (f->f_mode & FMODE_WRITE && !special_file(inode->i_mode)) {
#if 0
        error = get_write_access(inode);
        if (unlikely(error))
            goto cleanup_file;
        error = __mnt_want_write(f->f_path.mnt);
        if (unlikely(error)) {
            put_write_access(inode);
            goto cleanup_file;
        }
        f->f_mode |= FMODE_WRITER;
#endif
        panic("%s: FMODE_WRITE!\n", __func__);
    }

    /* POSIX.1-2008/SUSv4 Section XSI 2.9.7 */
    if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))
        f->f_mode |= FMODE_ATOMIC_POS;

    f->f_op = fops_get(inode->i_fop);
    if (WARN_ON(!f->f_op)) {
        error = -ENODEV;
        goto cleanup_all;
    }

#if 0
    error = break_lease(locks_inode(f), f->f_flags);
    if (error)
        goto cleanup_all;
#endif

    /* normally all 3 are set; ->open() can clear them if needed */
    f->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
    if (!open)
        open = f->f_op->open;
    if (open) {
        error = open(inode, f);
        if (error)
            goto cleanup_all;
    }
    f->f_mode |= FMODE_OPENED;
    if ((f->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
        i_readcount_inc(inode);
    if ((f->f_mode & FMODE_READ) &&
        likely(f->f_op->read || f->f_op->read_iter))
        f->f_mode |= FMODE_CAN_READ;
    if ((f->f_mode & FMODE_WRITE) &&
        likely(f->f_op->write || f->f_op->write_iter))
        f->f_mode |= FMODE_CAN_WRITE;

    f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

    file_ra_state_init(&f->f_ra, f->f_mapping->host->i_mapping);

    /* NB: we're sure to have correct a_ops only after f_op->open */
    if (f->f_flags & O_DIRECT) {
        if (!f->f_mapping->a_ops || !f->f_mapping->a_ops->direct_IO)
            return -EINVAL;
    }

    /*
     * XXX: Huge page cache doesn't support writing yet. Drop all page
     * cache for this file before processing writes.
     */
    if (f->f_mode & FMODE_WRITE) {
        panic("%s: FMODE_WRITE!\n", __func__);
    }

    return 0;

 cleanup_all:
    if (WARN_ON_ONCE(error > 0))
        error = -EINVAL;
    fops_put(f->f_op);
    if (f->f_mode & FMODE_WRITER) {
#if 0
        put_write_access(inode);
        __mnt_drop_write(f->f_path.mnt);
#endif
        panic("%s: FMODE_WRITER!\n", __func__);
    }
 cleanup_file:
    path_put(&f->f_path);
    f->f_path.mnt = NULL;
    f->f_path.dentry = NULL;
    f->f_inode = NULL;
    return error;
}

/**
 * vfs_open - open the file at the given path
 * @path: path to open
 * @file: newly allocated file with f_flag initialized
 * @cred: credentials to use
 */
int vfs_open(const struct path *path, struct file *file)
{
    file->f_path = *path;
    return do_dentry_open(file, d_backing_inode(path->dentry), NULL);
}

/*
 * "id" is the POSIX thread ID. We use the
 * files pointer for this..
 */
int filp_close(struct file *filp, fl_owner_t id)
{
    int retval = 0;

    if (!file_count(filp)) {
        printk(KERN_ERR "VFS: Close: file count is 0\n");
        return 0;
    }

    if (filp->f_op->flush)
        retval = filp->f_op->flush(filp, id);

    if (likely(!(filp->f_mode & FMODE_PATH))) {
#if 0
        dnotify_flush(filp, id);
        locks_remove_posix(filp, id);
#endif
        panic("%s: FMODE_PATH!\n", __func__);
    }
    fput(filp);
    return retval;
}
EXPORT_SYMBOL(filp_close);

/**
 * override_creds - Override the current process's subjective credentials
 * @new: The credentials to be assigned
 *
 * Install a set of temporary override subjective credentials on the current
 * process, returning the old set for later reversion.
 */
const struct cred *override_creds(const struct cred *new)
{
    const struct cred *old = current->cred;

    validate_creds(old);
    validate_creds(new);

    /*
     * NOTE! This uses 'get_new_cred()' rather than 'get_cred()'.
     *
     * That means that we do not clear the 'non_rcu' flag, since
     * we are only installing the cred into the thread-synchronous
     * '->cred' pointer, not the '->real_cred' pointer that is
     * visible to other threads under RCU.
     *
     * Also note that we did validate_creds() manually, not depending
     * on the validation in 'get_cred()'.
     */
    get_new_cred((struct cred *)new);
    rcu_assign_pointer(current->cred, new);

    return old;
}

/*
 * access() needs to use the real uid/gid, not the effective uid/gid.
 * We do this by temporarily clearing all FS-related capabilities and
 * switching the fsuid/fsgid around to the real ones.
 */
static const struct cred *access_override_creds(void)
{
    const struct cred *old_cred;
    struct cred *override_cred;

    override_cred = prepare_creds();
    if (!override_cred)
        return NULL;

    override_cred->fsuid = override_cred->uid;
    override_cred->fsgid = override_cred->gid;

    if (!issecure(SECURE_NO_SETUID_FIXUP)) {
        /* Clear the capabilities if we switch to a non-root user */
        kuid_t root_uid = make_kuid(override_cred->user_ns, 0);
#if 0
        if (!uid_eq(override_cred->uid, root_uid))
            cap_clear(override_cred->cap_effective);
        else
            override_cred->cap_effective = override_cred->cap_permitted;
#endif
    }

    /*
     * The new set of credentials can *only* be used in
     * task-synchronous circumstances, and does not need
     * RCU freeing, unless somebody then takes a separate
     * reference to it.
     *
     * NOTE! This is _only_ true because this credential
     * is used purely for override_creds() that installs
     * it as the subjective cred. Other threads will be
     * accessing ->real_cred, not the subjective cred.
     *
     * If somebody _does_ make a copy of this (using the
     * 'get_current_cred()' function), that will clear the
     * non_rcu field, because now that other user may be
     * expecting RCU freeing. But normal thread-synchronous
     * cred accesses will keep things non-RCY.
     */
    override_cred->non_rcu = 1;

    old_cred = override_creds(override_cred);

    /* override_cred() gets its own ref */
    put_cred(override_cred);

    return old_cred;
}

static long do_faccessat(int dfd, const char __user *filename,
                         int mode, int flags)
{
    struct path path;
    struct inode *inode;
    int res;
    unsigned int lookup_flags = LOOKUP_FOLLOW;
    const struct cred *old_cred = NULL;

    if (mode & ~S_IRWXO)    /* where's F_OK, X_OK, W_OK, R_OK? */
        return -EINVAL;

    if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
        return -EINVAL;

    if (flags & AT_SYMLINK_NOFOLLOW)
        lookup_flags &= ~LOOKUP_FOLLOW;
    if (flags & AT_EMPTY_PATH)
        lookup_flags |= LOOKUP_EMPTY;

#if 0
    if (!(flags & AT_EACCESS)) {
        old_cred = access_override_creds();
        if (!old_cred)
            return -ENOMEM;
    }
#endif

 retry:
    res = user_path_at(dfd, filename, lookup_flags, &path);
    if (res)
        goto out;

    panic("%s: END!\n", __func__);

 out_path_release:
    path_put(&path);
    if (retry_estale(res, lookup_flags)) {
        lookup_flags |= LOOKUP_REVAL;
        goto retry;
    }
 out:
    printk("%s: res(%d)\n", __func__, res);
#if 0
    if (old_cred)
        revert_creds(old_cred);
#endif

    return res;
}

SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename,
                int, mode)
{
    return do_faccessat(dfd, filename, mode, 0);
}

#define WILL_CREATE(flags)  (flags & (O_CREAT | __O_TMPFILE))
#define O_PATH_FLAGS    (O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC)

inline struct open_how build_open_how(int flags, umode_t mode)
{
    struct open_how how = {
        .flags = flags & VALID_OPEN_FLAGS,
        .mode = mode & S_IALLUGO,
    };

    /* O_PATH beats everything else. */
    if (how.flags & O_PATH)
        how.flags &= O_PATH_FLAGS;
    /* Modes should only be set for create-like flags. */
    if (!WILL_CREATE(how.flags))
        how.mode = 0;
    return how;
}

inline int build_open_flags(const struct open_how *how,
                            struct open_flags *op)
{
    u64 flags = how->flags;
    u64 strip = FMODE_NONOTIFY | O_CLOEXEC;
    int lookup_flags = 0;
    int acc_mode = ACC_MODE(flags);

    BUILD_BUG_ON_MSG(upper_32_bits(VALID_OPEN_FLAGS),
                     "struct open_flags doesn't yet handle "
                     "flags > 32 bits");

    /*
     * Strip flags that either shouldn't be set by userspace like
     * FMODE_NONOTIFY or that aren't relevant in determining struct
     * open_flags like O_CLOEXEC.
     */
    flags &= ~strip;

    /*
     * Older syscalls implicitly clear all of the invalid flags or argument
     * values before calling build_open_flags(), but openat2(2) checks all
     * of its arguments.
     */
    if (flags & ~VALID_OPEN_FLAGS)
        return -EINVAL;
    if (how->resolve & ~VALID_RESOLVE_FLAGS)
        return -EINVAL;

    /* Scoping flags are mutually exclusive. */
    if ((how->resolve & RESOLVE_BENEATH) &&
        (how->resolve & RESOLVE_IN_ROOT))
        return -EINVAL;

    /* Deal with the mode. */
    if (WILL_CREATE(flags)) {
        if (how->mode & ~S_IALLUGO)
            return -EINVAL;
        op->mode = how->mode | S_IFREG;
    } else {
        if (how->mode != 0)
            return -EINVAL;
        op->mode = 0;
    }

    /*
     * In order to ensure programs get explicit errors when trying to use
     * O_TMPFILE on old kernels, O_TMPFILE is implemented such that it
     * looks like (O_DIRECTORY|O_RDWR & ~O_CREAT) to old kernels. But we
     * have to require userspace to explicitly set it.
     */
    if (flags & __O_TMPFILE) {
        if ((flags & O_TMPFILE_MASK) != O_TMPFILE)
            return -EINVAL;
        if (!(acc_mode & MAY_WRITE))
            return -EINVAL;
    }
    if (flags & O_PATH) {
        /* O_PATH only permits certain other flags to be set. */
        if (flags & ~O_PATH_FLAGS)
            return -EINVAL;
        acc_mode = 0;
    }

    /*
     * O_SYNC is implemented as __O_SYNC|O_DSYNC.  As many places only
     * check for O_DSYNC if the need any syncing at all we enforce it's
     * always set instead of having to deal with possibly weird behaviour
     * for malicious applications setting only __O_SYNC.
     */
    if (flags & __O_SYNC)
        flags |= O_DSYNC;

    op->open_flag = flags;

    /* O_TRUNC implies we need access checks for write permissions */
    if (flags & O_TRUNC)
        acc_mode |= MAY_WRITE;

    /* Allow the LSM permission hook to distinguish append
       access from general write access. */
    if (flags & O_APPEND)
        acc_mode |= MAY_APPEND;

    op->acc_mode = acc_mode;

    op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

    if (flags & O_CREAT) {
        op->intent |= LOOKUP_CREATE;
        if (flags & O_EXCL) {
            op->intent |= LOOKUP_EXCL;
            flags |= O_NOFOLLOW;
        }
    }

    if (flags & O_DIRECTORY)
        lookup_flags |= LOOKUP_DIRECTORY;
    if (!(flags & O_NOFOLLOW))
        lookup_flags |= LOOKUP_FOLLOW;

    if (how->resolve & RESOLVE_NO_XDEV)
        lookup_flags |= LOOKUP_NO_XDEV;
    if (how->resolve & RESOLVE_NO_MAGICLINKS)
        lookup_flags |= LOOKUP_NO_MAGICLINKS;
    if (how->resolve & RESOLVE_NO_SYMLINKS)
        lookup_flags |= LOOKUP_NO_SYMLINKS;
    if (how->resolve & RESOLVE_BENEATH)
        lookup_flags |= LOOKUP_BENEATH;
    if (how->resolve & RESOLVE_IN_ROOT)
        lookup_flags |= LOOKUP_IN_ROOT;
    if (how->resolve & RESOLVE_CACHED) {
        /* Don't bother even trying for create/truncate/tmpfile open */
        if (flags & (O_TRUNC | O_CREAT | O_TMPFILE))
            return -EAGAIN;
        lookup_flags |= LOOKUP_CACHED;
    }

    op->lookup_flags = lookup_flags;
    return 0;
}

static long do_sys_openat2(int dfd, const char __user *filename,
                           struct open_how *how)
{
    struct open_flags op;
    int fd = build_open_flags(how, &op);
    struct filename *tmp;

    if (fd)
        return fd;

    tmp = getname(filename);
    if (IS_ERR(tmp))
        return PTR_ERR(tmp);

    printk("%s: filename(%s)\n", __func__, tmp->name);

    fd = get_unused_fd_flags(how->flags);
    if (fd >= 0) {
        struct file *f = do_filp_open(dfd, tmp, &op);
        if (IS_ERR(f)) {
            put_unused_fd(fd);
            fd = PTR_ERR(f);
        } else {
            fsnotify_open(f);
            fd_install(fd, f);
        }
    }
    putname(tmp);
    return fd;
}

long do_sys_open(int dfd, const char __user *filename, int flags,
                 umode_t mode)
{
    struct open_how how = build_open_how(flags, mode);
    return do_sys_openat2(dfd, filename, &how);
}

SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename,
                int, flags, umode_t, mode)
{
    if (force_o_largefile())
        flags |= O_LARGEFILE;
    return do_sys_open(dfd, filename, flags, mode);
}
