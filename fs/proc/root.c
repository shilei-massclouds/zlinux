// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/proc/root.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  proc root directory handling functions
 */

#include <linux/uaccess.h>

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/sched.h>
//#include <linux/sched/stat.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/user_namespace.h>
#include <linux/fs_context.h>
#include <linux/mount.h>
#include <linux/pid_namespace.h>
#include <linux/fs_parser.h>
#include <linux/cred.h>
#include <linux/magic.h>
#include <linux/slab.h>

#include "internal.h"

struct proc_fs_context {
    struct pid_namespace    *pid_ns;
    unsigned int        mask;
    enum proc_hidepid   hidepid;
    int                 gid;
    enum proc_pidonly   pidonly;
};

enum proc_param {
    Opt_gid,
    Opt_hidepid,
    Opt_subset,
};

static int proc_root_readdir(struct file *file, struct dir_context *ctx)
{
#if 0
    if (ctx->pos < FIRST_PROCESS_ENTRY) {
        int error = proc_readdir(file, ctx);
        if (unlikely(error <= 0))
            return error;
        ctx->pos = FIRST_PROCESS_ENTRY;
    }

    return proc_pid_readdir(file, ctx);
#endif
    panic("%s: END!\n", __func__);
}

static struct dentry *
proc_root_lookup(struct inode * dir, struct dentry * dentry, unsigned int flags)
{
#if 0
    if (!proc_pid_lookup(dentry, flags))
        return NULL;

    return proc_lookup(dir, dentry, flags);
#endif
    panic("%s: END!\n", __func__);
}

static int proc_root_getattr(struct user_namespace *mnt_userns,
                             const struct path *path, struct kstat *stat,
                             u32 request_mask, unsigned int query_flags)
{
#if 0
    generic_fillattr(&init_user_ns, d_inode(path->dentry), stat);
    stat->nlink = proc_root.nlink + nr_processes();
    return 0;
#endif
    panic("%s: END!\n", __func__);
}

/*
 * The root /proc directory is special, as it has the
 * <pid> directories. Thus we don't use the generic
 * directory handling functions for that..
 */
static const struct file_operations proc_root_operations = {
    .read           = generic_read_dir,
    .iterate_shared = proc_root_readdir,
    .llseek         = generic_file_llseek,
};

/*
 * proc root can do almost nothing..
 */
static const struct inode_operations proc_root_inode_operations = {
    .lookup     = proc_root_lookup,
    .getattr    = proc_root_getattr,
};

/*
 * This is the root "inode" in the /proc tree..
 */
struct proc_dir_entry proc_root = {
    .low_ino    = PROC_ROOT_INO,
    .namelen    = 5,
    .mode       = S_IFDIR | S_IRUGO | S_IXUGO,
    .nlink      = 2,
    .refcnt     = REFCOUNT_INIT(1),
    .proc_iops  = &proc_root_inode_operations,
    .proc_dir_ops   = &proc_root_operations,
    .parent     = &proc_root,
    .subdir     = RB_ROOT,
    .name       = "/proc",
};

static const struct fs_parameter_spec proc_fs_parameters[] = {
    fsparam_u32("gid",  Opt_gid),
    fsparam_string("hidepid",   Opt_hidepid),
    fsparam_string("subset",    Opt_subset),
    {}
};

static void proc_fs_context_free(struct fs_context *fc)
{
    struct proc_fs_context *ctx = fc->fs_private;

    put_pid_ns(ctx->pid_ns);
    kfree(ctx);
}

static int proc_reconfigure(struct fs_context *fc)
{
#if 0
    struct super_block *sb = fc->root->d_sb;
    struct proc_fs_info *fs_info = proc_sb_info(sb);

    sync_filesystem(sb);

    proc_apply_options(fs_info, fc, current_user_ns());
    return 0;
#endif
    panic("%s: END!\n", __func__);
}

static int proc_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    panic("%s: END!\n", __func__);
}

static int proc_fill_super(struct super_block *s, struct fs_context *fc)
{
    panic("%s: END!\n", __func__);
}

static int proc_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, proc_fill_super);
}

static const struct fs_context_operations proc_fs_context_ops = {
    .free           = proc_fs_context_free,
    .parse_param    = proc_parse_param,
    .get_tree       = proc_get_tree,
    .reconfigure    = proc_reconfigure,
};

static int proc_init_fs_context(struct fs_context *fc)
{
    struct proc_fs_context *ctx;

    ctx = kzalloc(sizeof(struct proc_fs_context), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    ctx->pid_ns = get_pid_ns(task_active_pid_ns(current));
    put_user_ns(fc->user_ns);
    fc->user_ns = get_user_ns(ctx->pid_ns->user_ns);
    fc->fs_private = ctx;
    fc->ops = &proc_fs_context_ops;
    return 0;
}

static void proc_kill_sb(struct super_block *sb)
{
    struct proc_fs_info *fs_info = proc_sb_info(sb);

    if (!fs_info) {
        kill_anon_super(sb);
        return;
    }

    dput(fs_info->proc_self);
    dput(fs_info->proc_thread_self);

    kill_anon_super(sb);
    put_pid_ns(fs_info->pid_ns);
    kfree(fs_info);
}

static struct file_system_type proc_fs_type = {
    .name           = "proc",
    .init_fs_context    = proc_init_fs_context,
    .parameters     = proc_fs_parameters,
    .kill_sb        = proc_kill_sb,
    .fs_flags       = FS_USERNS_MOUNT | FS_DISALLOW_NOTIFY_PERM,
};

void __init proc_root_init(void)
{
    proc_init_kmemcache();
    set_proc_pid_nlink();
    proc_self_init();
#if 0
    proc_thread_self_init();
    proc_symlink("mounts", NULL, "self/mounts");

    proc_net_init();
#endif
    proc_mkdir("fs", NULL);
    proc_mkdir("driver", NULL);
#if 0
    /* somewhere for the nfsd filesystem to be mounted */
    proc_create_mount_point("fs/nfsd");
    proc_tty_init();
#endif
    proc_mkdir("bus", NULL);
#if 0
    proc_sys_init();
#endif

    register_filesystem(&proc_fs_type);
}
