/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Internal procfs definitions
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>

struct ctl_table_header;
struct mempolicy;

/*
 * This is not completely implemented yet. The idea is to
 * create an in-memory tree (like the actual /proc filesystem
 * tree) of these proc_dir_entries, so that we can dynamically
 * add new files to /proc.
 *
 * parent/subdir are used for the directory structure (every /proc file has a
 * parent, but "subdir" is empty for all non-directory entries).
 * subdir_node is used to build the rb tree "subdir" of the parent.
 */
struct proc_dir_entry {
    /*
     * number of callers into module in progress;
     * negative -> it's going away RSN
     */
    atomic_t in_use;
    refcount_t refcnt;
    struct list_head pde_openers;   /* who did ->open, but not ->release */
    /* protects ->pde_openers and all struct pde_opener instances */
    spinlock_t pde_unload_lock;
    struct completion *pde_unload_completion;
    const struct inode_operations *proc_iops;
    union {
        const struct proc_ops *proc_ops;
        const struct file_operations *proc_dir_ops;
    };
    const struct dentry_operations *proc_dops;
    union {
        const struct seq_operations *seq_ops;
        int (*single_show)(struct seq_file *, void *);
    };
    proc_write_t write;
    void *data;
    unsigned int state_size;
    unsigned int low_ino;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    struct proc_dir_entry *parent;
    struct rb_root subdir;
    struct rb_node subdir_node;
    char *name;
    umode_t mode;
    u8 flags;
    u8 namelen;
    char inline_name[];
} __randomize_layout;

#define SIZEOF_PDE  (               \
    sizeof(struct proc_dir_entry) < 128 ? 128 : \
    sizeof(struct proc_dir_entry) < 192 ? 192 : \
    sizeof(struct proc_dir_entry) < 256 ? 256 : \
    sizeof(struct proc_dir_entry) < 512 ? 512 : \
    0)
#define SIZEOF_PDE_INLINE_NAME (SIZEOF_PDE - sizeof(struct proc_dir_entry))

union proc_op {
    int (*proc_get_link)(struct dentry *, struct path *);
    int (*proc_show)(struct seq_file *m,
                     struct pid_namespace *ns,
                     struct pid *pid,
                     struct task_struct *task);
    const char *lsm;
};

struct proc_inode {
    struct pid *pid;
    unsigned int fd;
    union proc_op op;
    struct proc_dir_entry *pde;
    struct ctl_table_header *sysctl;
    struct ctl_table *sysctl_entry;
    struct hlist_node sibling_inodes;
    const struct proc_ns_operations *ns_ops;
    struct inode vfs_inode;
} __randomize_layout;

/*
 * General functions
 */
static inline struct proc_inode *PROC_I(const struct inode *inode)
{
    return container_of(inode, struct proc_inode, vfs_inode);
}

static inline struct proc_dir_entry *PDE(const struct inode *inode)
{
    return PROC_I(inode)->pde;
}

void proc_init_kmemcache(void);

void set_proc_pid_nlink(void);

extern const struct inode_operations proc_pid_link_inode_operations;

extern void proc_self_init(void);

/*
 * root.c
 */
extern struct proc_dir_entry proc_root;

unsigned name_to_int(const struct qstr *qstr);

static inline bool is_empty_pde(const struct proc_dir_entry *pde)
{
    return S_ISDIR(pde->mode) && !pde->proc_iops;
}

extern struct kmem_cache *proc_dir_entry_cache;
void pde_free(struct proc_dir_entry *pde);

/*
 * inode.c
 */
struct pde_opener {
    struct list_head lh;
    struct file *file;
    bool closing;
    struct completion *c;
} __randomize_layout;

extern const struct dentry_operations proc_net_dentry_ops;
static inline void pde_force_lookup(struct proc_dir_entry *pde)
{
    /* /proc/net/ entries can be changed under us by setns(CLONE_NEWNET) */
    pde->proc_dops = &proc_net_dentry_ops;
}
