/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SHMEM_FS_H
#define __SHMEM_FS_H

#if 0
#include <linux/file.h>
#include <linux/swap.h>
#include <linux/mempolicy.h>
#include <linux/xattr.h>
#endif
#include <linux/pagemap.h>
#include <linux/percpu_counter.h>
#include <linux/fs_parser.h>

/* inode in-kernel data */

struct shmem_inode_info {
    spinlock_t          lock;
    unsigned int        seals;      /* shmem seals */
    unsigned long       flags;
    unsigned long       alloced;    /* data pages alloced to file */
    unsigned long       swapped;    /* subtotal assigned to swap */
    pgoff_t             fallocend;  /* highest fallocate endindex */
    struct list_head    shrinklist;     /* shrinkable hpage inodes */
    struct list_head    swaplist;   /* chain of maybes on swap */
    //struct simple_xattrs    xattrs;     /* list of xattrs */
    atomic_t            stop_eviction;  /* hold when working on inode */
    struct timespec64   i_crtime;   /* file creation time */
    struct inode        vfs_inode;
};

struct shmem_sb_info {
    unsigned long max_blocks;   /* How many blocks are allowed */
    struct percpu_counter used_blocks;  /* How many are allocated */
    unsigned long max_inodes;   /* How many inodes are allowed */
    unsigned long free_inodes;  /* How many are left for allocation */
    raw_spinlock_t stat_lock;   /* Serialize shmem_sb_info changes */
    umode_t mode;           /* Mount mode for root directory */
    unsigned char huge;     /* Whether to try for hugepages */
    kuid_t uid;         /* Mount uid for root directory */
    kgid_t gid;         /* Mount gid for root directory */
    bool full_inums;        /* If i_ino should be uint or ino_t */
    ino_t next_ino;         /* The next per-sb inode number to use */
    ino_t __percpu *ino_batch;  /* The next per-cpu inode number to use */
    spinlock_t shrinklist_lock;   /* Protects shrinklist */
    struct list_head shrinklist;  /* List of shinkable inodes */
    unsigned long shrinklist_len; /* Length of shrinklist */
};

extern int shmem_init(void);
extern int shmem_init_fs_context(struct fs_context *fc);

static inline struct shmem_inode_info *SHMEM_I(struct inode *inode)
{
    return container_of(inode, struct shmem_inode_info, vfs_inode);
}

extern const struct address_space_operations shmem_aops;
static inline bool shmem_mapping(struct address_space *mapping)
{
    return mapping->a_ops == &shmem_aops;
}

extern unsigned long
shmem_get_unmapped_area(struct file *, unsigned long addr,
                        unsigned long len, unsigned long pgoff,
                        unsigned long flags);

#endif /* __SHMEM_FS_H */
