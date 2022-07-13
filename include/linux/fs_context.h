/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Filesystem superblock creation and reconfiguration context.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_FS_CONTEXT_H
#define _LINUX_FS_CONTEXT_H

#include <linux/kernel.h>
#include <linux/refcount.h>
#include <linux/errno.h>
#if 0
#include <linux/security.h>
#endif
#include <linux/mutex.h>

struct cred;
struct dentry;
struct file_operations;
struct file_system_type;
struct mnt_namespace;
struct net;
struct pid_namespace;
struct super_block;
struct user_namespace;
struct vfsmount;
struct path;

enum fs_context_purpose {
    FS_CONTEXT_FOR_MOUNT,       /* New superblock for explicit mount */
    FS_CONTEXT_FOR_SUBMOUNT,    /* New superblock for automatic submount */
    FS_CONTEXT_FOR_RECONFIGURE, /* Superblock reconfiguration (remount) */
};


/*
 * Filesystem context for holding the parameters used in the creation or
 * reconfiguration of a superblock.
 *
 * Superblock creation fills in ->root whereas reconfiguration begins with this
 * already set.
 *
 * See Documentation/filesystems/mount_api.rst
 */
struct fs_context {
    const struct fs_context_operations *ops;
    struct mutex        uapi_mutex; /* Userspace access mutex */
    struct file_system_type *fs_type;
    void            *fs_private;    /* The filesystem's context */
    void            *sget_key;
#if 0
    struct dentry       *root;      /* The root and superblock */
    struct user_namespace   *user_ns;   /* The user namespace for this mount */
    struct net      *net_ns;    /* The network namespace for this mount */
    const struct cred   *cred;      /* The mounter's credentials */
    struct p_log        log;        /* Logging buffer */
#endif
    const char      *source;    /* The source name (eg. dev path) */
    void            *security;  /* Linux S&M options */
    void            *s_fs_info; /* Proposed s_fs_info */
    unsigned int    sb_flags;   /* Proposed superblock flags (SB_*) */
    unsigned int    sb_flags_mask;  /* Superblock flags that were changed */
    unsigned int    s_iflags;   /* OR'd with sb->s_iflags */
    unsigned int    lsm_flags;  /* Information flags from the fs to the LSM */
    enum fs_context_purpose purpose:8;
#if 0
    enum fs_context_phase   phase:8;    /* The phase the context is in */
#endif
    bool            need_free:1;    /* Need to call ops->free() */
    bool            global:1;   /* Goes into &init_user_ns */
    bool            oldapi:1;   /* Coming from mount(2) */
};

struct fs_context_operations {
    void (*free)(struct fs_context *fc);
    int (*dup)(struct fs_context *fc, struct fs_context *src_fc);
    int (*parse_param)(struct fs_context *fc, struct fs_parameter *param);
    int (*parse_monolithic)(struct fs_context *fc, void *data);
    int (*get_tree)(struct fs_context *fc);
    int (*reconfigure)(struct fs_context *fc);
};

/*
 * fs_context manipulation functions.
 */
extern struct fs_context *
fs_context_for_mount(struct file_system_type *fs_type, unsigned int sb_flags);

#endif /* _LINUX_FS_CONTEXT_H */
