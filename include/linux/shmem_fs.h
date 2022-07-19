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
#if 0
    ino_t next_ino;         /* The next per-sb inode number to use */
    ino_t __percpu *ino_batch;  /* The next per-cpu inode number to use */
#endif
    spinlock_t shrinklist_lock;   /* Protects shrinklist */
    struct list_head shrinklist;  /* List of shinkable inodes */
    unsigned long shrinklist_len; /* Length of shrinklist */
};

extern int shmem_init(void);
extern int shmem_init_fs_context(struct fs_context *fc);

#endif /* __SHMEM_FS_H */
