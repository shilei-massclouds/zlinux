// SPDX-License-Identifier: GPL-2.0-only
/*
 * proc/fs/generic.c --- generic routines for the proc-fs
 *
 * This file contains generic proc-fs routines for handling
 * directories and files.
 *
 * Copyright (C) 1991, 1992 Linus Torvalds.
 * Copyright (C) 1997 Theodore Ts'o
 */

#include <linux/cache.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/mount.h>
#include <linux/init.h>
#include <linux/idr.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/uaccess.h>
//#include <linux/seq_file.h>

#include "internal.h"

struct kmem_cache *proc_dir_entry_cache __ro_after_init;

void pde_free(struct proc_dir_entry *pde)
{
    if (S_ISLNK(pde->mode))
        kfree(pde->data);
    if (pde->name != pde->inline_name)
        kfree(pde->name);
    kmem_cache_free(proc_dir_entry_cache, pde);
}

static DEFINE_IDA(proc_inum_ida);
static DEFINE_RWLOCK(proc_subdir_lock);

static int proc_net_d_revalidate(struct dentry *dentry, unsigned int flags)
{
    return 0;
}

const struct dentry_operations proc_net_dentry_ops = {
    .d_revalidate   = proc_net_d_revalidate,
    .d_delete       = always_delete_dentry,
};

static int proc_misc_d_revalidate(struct dentry *dentry, unsigned int flags)
{
    if (flags & LOOKUP_RCU)
        return -ECHILD;

    if (atomic_read(&PDE(d_inode(dentry))->in_use) < 0)
        return 0; /* revalidate */
    return 1;
}

static int proc_misc_d_delete(const struct dentry *dentry)
{
    return atomic_read(&PDE(d_inode(dentry))->in_use) < 0;
}

static const struct dentry_operations proc_misc_dentry_ops = {
    .d_revalidate   = proc_misc_d_revalidate,
    .d_delete       = proc_misc_d_delete,
};

#define PROC_DYNAMIC_FIRST 0xF0000000U

/*
 * Return an inode number between PROC_DYNAMIC_FIRST and
 * 0xffffffff, or zero on failure.
 */
int proc_alloc_inum(unsigned int *inum)
{
    int i;

    i = ida_simple_get(&proc_inum_ida, 0, UINT_MAX - PROC_DYNAMIC_FIRST + 1,
                       GFP_KERNEL);
    if (i < 0)
        return i;

    *inum = PROC_DYNAMIC_FIRST + (unsigned int)i;
    return 0;
}

static int proc_match(const char *name, struct proc_dir_entry *de,
                      unsigned int len)
{
    if (len < de->namelen)
        return -1;
    if (len > de->namelen)
        return 1;

    return memcmp(name, de->name, len);
}

void proc_set_user(struct proc_dir_entry *de, kuid_t uid, kgid_t gid)
{
    de->uid = uid;
    de->gid = gid;
}
EXPORT_SYMBOL(proc_set_user);

static struct proc_dir_entry *
pde_subdir_find(struct proc_dir_entry *dir, const char *name, unsigned int len)
{
    struct rb_node *node = dir->subdir.rb_node;

    while (node) {
        struct proc_dir_entry *de = rb_entry(node, struct proc_dir_entry,
                                             subdir_node);
        int result = proc_match(name, de, len);

        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else
            return de;
    }
    return NULL;
}

/*
 * This function parses a name such as "tty/driver/serial", and
 * returns the struct proc_dir_entry for "/proc/tty/driver", and
 * returns "serial" in residual.
 */
static int __xlate_proc_name(const char *name, struct proc_dir_entry **ret,
                             const char **residual)
{
    const char *cp = name, *next;
    struct proc_dir_entry *de;

    de = *ret ?: &proc_root;
    while ((next = strchr(cp, '/')) != NULL) {
        de = pde_subdir_find(de, cp, next - cp);
        if (!de) {
            WARN(1, "name '%s'\n", name);
            return -ENOENT;
        }
        cp = next + 1;
    }
    *residual = cp;
    *ret = de;
    return 0;
}

static int xlate_proc_name(const char *name, struct proc_dir_entry **ret,
                           const char **residual)
{
    int rv;

    read_lock(&proc_subdir_lock);
    rv = __xlate_proc_name(name, ret, residual);
    read_unlock(&proc_subdir_lock);
    return rv;
}

static struct proc_dir_entry *
__proc_create(struct proc_dir_entry **parent, const char *name, umode_t mode,
              nlink_t nlink)
{
    struct proc_dir_entry *ent = NULL;
    const char *fn;
    struct qstr qstr;

    if (xlate_proc_name(name, parent, &fn) != 0)
        goto out;
    qstr.name = fn;
    qstr.len = strlen(fn);
    if (qstr.len == 0 || qstr.len >= 256) {
        WARN(1, "name len %u\n", qstr.len);
        return NULL;
    }
    if (qstr.len == 1 && fn[0] == '.') {
        WARN(1, "name '.'\n");
        return NULL;
    }
    if (qstr.len == 2 && fn[0] == '.' && fn[1] == '.') {
        WARN(1, "name '..'\n");
        return NULL;
    }
    if (*parent == &proc_root && name_to_int(&qstr) != ~0U) {
        WARN(1, "create '/proc/%s' by hand\n", qstr.name);
        return NULL;
    }
    if (is_empty_pde(*parent)) {
        WARN(1, "attempt to add to permanently empty directory");
        return NULL;
    }

    ent = kmem_cache_zalloc(proc_dir_entry_cache, GFP_KERNEL);
    if (!ent)
        goto out;

    if (qstr.len + 1 <= SIZEOF_PDE_INLINE_NAME) {
        ent->name = ent->inline_name;
    } else {
        ent->name = kmalloc(qstr.len + 1, GFP_KERNEL);
        if (!ent->name) {
            pde_free(ent);
            return NULL;
        }
    }

    memcpy(ent->name, fn, qstr.len + 1);
    ent->namelen = qstr.len;
    ent->mode = mode;
    ent->nlink = nlink;
    ent->subdir = RB_ROOT;
    refcount_set(&ent->refcnt, 1);
    spin_lock_init(&ent->pde_unload_lock);
    INIT_LIST_HEAD(&ent->pde_openers);
    proc_set_user(ent, (*parent)->uid, (*parent)->gid);

    ent->proc_dops = &proc_misc_dentry_ops;

 out:
    return ent;
}

int proc_readdir(struct file *file, struct dir_context *ctx)
{
#if 0
    struct inode *inode = file_inode(file);
    struct proc_fs_info *fs_info = proc_sb_info(inode->i_sb);

    if (fs_info->pidonly == PROC_PIDONLY_ON)
        return 1;

    return proc_readdir_de(file, ctx, PDE(inode));
#endif
    panic("%s: END!\n", __func__);
}

struct dentry *proc_lookup(struct inode *dir, struct dentry *dentry,
                           unsigned int flags)
{
#if 0
    struct proc_fs_info *fs_info = proc_sb_info(dir->i_sb);

    if (fs_info->pidonly == PROC_PIDONLY_ON)
        return ERR_PTR(-ENOENT);

    return proc_lookup_de(dir, dentry, PDE(dir));
#endif
    panic("%s: END!\n", __func__);
}

static int proc_getattr(struct user_namespace *mnt_userns,
                        const struct path *path, struct kstat *stat,
                        u32 request_mask, unsigned int query_flags)
{
#if 0
    struct inode *inode = d_inode(path->dentry);
    struct proc_dir_entry *de = PDE(inode);
    if (de) {
        nlink_t nlink = READ_ONCE(de->nlink);
        if (nlink > 0) {
            set_nlink(inode, nlink);
        }
    }

    generic_fillattr(&init_user_ns, inode, stat);
    return 0;
#endif
    panic("%s: END!\n", __func__);
}

static int proc_notify_change(struct user_namespace *mnt_userns,
                              struct dentry *dentry, struct iattr *iattr)
{
#if 0
    struct inode *inode = d_inode(dentry);
    struct proc_dir_entry *de = PDE(inode);
    int error;

    error = setattr_prepare(&init_user_ns, dentry, iattr);
    if (error)
        return error;

    setattr_copy(&init_user_ns, inode, iattr);
    mark_inode_dirty(inode);

    proc_set_user(de, inode->i_uid, inode->i_gid);
    de->mode = inode->i_mode;
    return 0;
#endif
    panic("%s: END!\n", __func__);
}

/*
 * These are the generic /proc directory operations. They
 * use the in-memory "struct proc_dir_entry" tree to parse
 * the /proc directory.
 */
static const struct file_operations proc_dir_operations = {
    .llseek             = generic_file_llseek,
    .read               = generic_read_dir,
    .iterate_shared     = proc_readdir,
};

/*
 * proc directories can do almost nothing..
 */
static const struct inode_operations proc_dir_inode_operations = {
    .lookup     = proc_lookup,
    .getattr    = proc_getattr,
    .setattr    = proc_notify_change,
};

static bool pde_subdir_insert(struct proc_dir_entry *dir,
                              struct proc_dir_entry *de)
{
    struct rb_root *root = &dir->subdir;
    struct rb_node **new = &root->rb_node, *parent = NULL;

    /* Figure out where to put new node */
    while (*new) {
        struct proc_dir_entry *this = rb_entry(*new, struct proc_dir_entry,
                                               subdir_node);
        int result = proc_match(de->name, this, de->namelen);

        parent = *new;
        if (result < 0)
            new = &(*new)->rb_left;
        else if (result > 0)
            new = &(*new)->rb_right;
        else
            return false;
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&de->subdir_node, parent, new);
    rb_insert_color(&de->subdir_node, root);
    return true;
}

void proc_free_inum(unsigned int inum)
{
    ida_simple_remove(&proc_inum_ida, inum - PROC_DYNAMIC_FIRST);
}

/* returns the registered entry, or frees dp and returns NULL on failure */
struct proc_dir_entry *proc_register(struct proc_dir_entry *dir,
                                     struct proc_dir_entry *dp)
{
    if (proc_alloc_inum(&dp->low_ino))
        goto out_free_entry;

    write_lock(&proc_subdir_lock);
    dp->parent = dir;
    if (pde_subdir_insert(dir, dp) == false) {
        WARN(1, "proc_dir_entry '%s/%s' already registered\n",
             dir->name, dp->name);
        write_unlock(&proc_subdir_lock);
        goto out_free_inum;
    }
    dir->nlink++;
    write_unlock(&proc_subdir_lock);

    return dp;

 out_free_inum:
    proc_free_inum(dp->low_ino);
 out_free_entry:
    pde_free(dp);
    return NULL;
}

struct proc_dir_entry *_proc_mkdir(const char *name, umode_t mode,
                                   struct proc_dir_entry *parent, void *data,
                                   bool force_lookup)
{
    struct proc_dir_entry *ent;

    if (mode == 0)
        mode = S_IRUGO | S_IXUGO;

    ent = __proc_create(&parent, name, S_IFDIR | mode, 2);
    if (ent) {
        ent->data = data;
        ent->proc_dir_ops = &proc_dir_operations;
        ent->proc_iops = &proc_dir_inode_operations;
        if (force_lookup) {
            pde_force_lookup(ent);
        }
        ent = proc_register(parent, ent);
    }
    return ent;
}
EXPORT_SYMBOL_GPL(_proc_mkdir);

struct proc_dir_entry *proc_mkdir_data(const char *name, umode_t mode,
                                       struct proc_dir_entry *parent,
                                       void *data)
{
    return _proc_mkdir(name, mode, parent, data, false);
}
EXPORT_SYMBOL_GPL(proc_mkdir_data);

struct proc_dir_entry *proc_mkdir(const char *name,
                                  struct proc_dir_entry *parent)
{
    return proc_mkdir_data(name, 0, parent, NULL);
}
EXPORT_SYMBOL(proc_mkdir);
