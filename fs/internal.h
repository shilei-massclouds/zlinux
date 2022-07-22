/* SPDX-License-Identifier: GPL-2.0-or-later */
/* fs/ internal definitions
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

struct super_block;
struct file_system_type;
struct iomap;
struct iomap_ops;
struct linux_binprm;
struct path;
struct mount;
struct shrink_control;
struct fs_context;
struct user_namespace;
struct pipe_inode_info;

extern void __init mnt_init(void);

/*
 * block/bdev.c
 */
extern void __init bdev_cache_init(void);

extern int parse_monolithic_mount_data(struct fs_context *, void *);

/*
 * namei.c
 */
extern int filename_lookup(int dfd, struct filename *name, unsigned flags,
                           struct path *path, struct path *root);
extern int vfs_path_lookup(struct dentry *, struct vfsmount *,
                           const char *, unsigned int, struct path *);
int do_rmdir(int dfd, struct filename *name);
int do_unlinkat(int dfd, struct filename *name);
int may_linkat(struct user_namespace *mnt_userns, struct path *link);
int do_renameat2(int olddfd, struct filename *oldname, int newdfd,
                 struct filename *newname, unsigned int flags);
int do_mkdirat(int dfd, struct filename *name, umode_t mode);
int do_symlinkat(struct filename *from, int newdfd, struct filename *to);
int do_linkat(int olddfd, struct filename *old, int newdfd,
              struct filename *new, int flags);
