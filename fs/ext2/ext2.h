/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/include/linux/minix_fs.h
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */
#include <linux/fs.h>
#if 0
#include <linux/ext2_fs.h>
#include <linux/blockgroup_lock.h>
#endif
#include <linux/percpu_counter.h>
#include <linux/rbtree.h>
#include <linux/mm.h>
#include <linux/highmem.h>

/*
 * second extended file system inode data in memory
 */
struct ext2_inode_info {
    __le32  i_data[15];
    __u32   i_flags;
    __u32   i_faddr;
    __u8    i_frag_no;
    __u8    i_frag_size;
    __u16   i_state;
    __u32   i_file_acl;
    __u32   i_dir_acl;
    __u32   i_dtime;

    /*
     * i_block_group is the number of the block group which contains
     * this file's inode.  Constant across the lifetime of the inode,
     * it is used for making block allocation decisions - we try to
     * place a file's data blocks near its inode block, and new inodes
     * near to their parent directory's inode.
     */
    __u32   i_block_group;

    /* block reservation info */
    struct ext2_block_alloc_info *i_block_alloc_info;

    __u32   i_dir_start_lookup;

    rwlock_t i_meta_lock;

    /*
     * truncate_mutex is for serialising ext2_truncate() against
     * ext2_getblock().  It also protects the internals of the inode's
     * reservation data structures: ext2_reserve_window and
     * ext2_reserve_window_node.
     */
    struct mutex truncate_mutex;
    struct inode    vfs_inode;
    struct list_head i_orphan;  /* unlinked but open inodes */
};
