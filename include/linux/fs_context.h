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
 * Type of parameter value.
 */
enum fs_value_type {
    fs_value_is_undefined,
    fs_value_is_flag,       /* Value not given a value */
    fs_value_is_string,     /* Value is a string */
    fs_value_is_blob,       /* Value is a binary blob */
    fs_value_is_filename,       /* Value is a filename* + dirfd */
    fs_value_is_file,       /* Value is a file* */
};

/*
 * Configuration parameter.
 */
struct fs_parameter {
    const char      *key;       /* Parameter name */
    enum fs_value_type  type:8;     /* The type of value here */
    union {
        char        *string;
        void        *blob;
        struct filename *name;
        struct file *file;
    };
    size_t  size;
    int dirfd;
};

/*
 * Mount error, warning and informational message logging.  This structure is
 * shareable between a mount and a subordinate mount.
 */
struct fc_log {
    refcount_t  usage;
    u8      head;           /* Insertion index in buffer[] */
    u8      tail;           /* Removal index in buffer[] */
    u8      need_free;      /* Mask of kfree'able items in buffer[] */
    struct module *owner;   /* Owner module for strings
                               that don't then need freeing */
    char    *buffer[8];
};

struct p_log {
    const char *prefix;
    struct fc_log *log;
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
    struct mutex uapi_mutex; /* Userspace access mutex */
    struct file_system_type *fs_type;
    void *fs_private;   /* The filesystem's context */
    void *sget_key;
    struct dentry *root;      /* The root and superblock */
    struct user_namespace *user_ns;   /* The user namespace for this mount */
#if 0
    struct net *net_ns;    /* The network namespace for this mount */
#endif
    const struct cred *cred;      /* The mounter's credentials */
    struct p_log    log;        /* Logging buffer */
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
 * sget() wrappers to be called from the ->get_tree() op.
 */
enum vfs_get_super_keying {
    vfs_get_single_super,       /* Only one such superblock may exist */
    vfs_get_single_reconf_super, /* As above, but reconfigure if it exists */
    vfs_get_keyed_super,        /* Superblocks with different s_fs_info keys
                                   may exist */
    vfs_get_independent_super,  /* Multiple independent superblocks may exist */
};

extern int vfs_get_super(struct fs_context *fc,
                         enum vfs_get_super_keying keying,
                         int (*fill_super)(struct super_block *sb,
                                           struct fs_context *fc));

extern int get_tree_nodev(struct fs_context *fc,
                          int (*fill_super)(struct super_block *sb,
                                            struct fs_context *fc));

/*
 * fs_context manipulation functions.
 */
extern struct fs_context *
fs_context_for_mount(struct file_system_type *fs_type, unsigned int sb_flags);

extern int vfs_parse_fs_string(struct fs_context *fc, const char *key,
                               const char *value, size_t v_size);

extern int vfs_parse_fs_param(struct fs_context *fc,
                              struct fs_parameter *param);

extern int vfs_get_tree(struct fs_context *fc);
extern void put_fs_context(struct fs_context *fc);

extern __attribute__((format(printf, 4, 5)))
void logfc(struct fc_log *log, const char *prefix, char level,
           const char *fmt, ...);

#define __logfc(fc, l, fmt, ...) \
    logfc((fc)->log.log, NULL, l, fmt, ## __VA_ARGS__)

/**
 * errorf - Store supplementary error message
 * @fc: The context in which to log the error message
 * @fmt: The format string
 *
 * Store the supplementary error message for the process if the process has
 * enabled the facility.
 */
#define errorf(fc, fmt, ...) __logfc(fc, 'e', fmt, ## __VA_ARGS__)

/**
 * invalf - Store supplementary invalid argument error message
 * @fc: The context in which to log the error message
 * @fmt: The format string
 *
 * Store the supplementary error message for the process if the process has
 * enabled the facility and return -EINVAL.
 */
#define invalf(fc, fmt, ...) (errorf(fc, fmt, ## __VA_ARGS__), -EINVAL)

#endif /* _LINUX_FS_CONTEXT_H */
