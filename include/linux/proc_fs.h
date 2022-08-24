/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The proc filesystem constants/structures
 */
#ifndef _LINUX_PROC_FS_H
#define _LINUX_PROC_FS_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/fs.h>

struct proc_dir_entry;
struct seq_file;
struct seq_operations;

/* definitions for hide_pid field */
enum proc_hidepid {
    HIDEPID_OFF             = 0,
    HIDEPID_NO_ACCESS       = 1,
    HIDEPID_INVISIBLE       = 2,
    HIDEPID_NOT_PTRACEABLE  = 4, /* Limit pids to only ptraceable pids */
};

/* definitions for proc mount option pidonly */
enum proc_pidonly {
    PROC_PIDONLY_OFF = 0,
    PROC_PIDONLY_ON  = 1,
};

struct proc_fs_info {
    struct pid_namespace *pid_ns;
    struct dentry *proc_self;        /* For /proc/self */
    struct dentry *proc_thread_self; /* For /proc/thread-self */
    kgid_t pid_gid;
    enum proc_hidepid hide_pid;
    enum proc_pidonly pidonly;
};

extern void proc_root_init(void);

struct proc_dir_entry *_proc_mkdir(const char *, umode_t,
                                   struct proc_dir_entry *, void *, bool);
extern struct proc_dir_entry *proc_mkdir(const char *, struct proc_dir_entry *);
extern struct proc_dir_entry *proc_mkdir_data(const char *, umode_t,
                                              struct proc_dir_entry *, void *);
extern struct proc_dir_entry *proc_mkdir_mode(const char *, umode_t,
                                              struct proc_dir_entry *);
struct proc_dir_entry *proc_create_mount_point(const char *name);

typedef int (*proc_write_t)(struct file *, char *, size_t);

static inline struct proc_fs_info *proc_sb_info(struct super_block *sb)
{
    return sb->s_fs_info;
}

#endif /* _LINUX_PROC_FS_H */
