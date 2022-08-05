// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext2/balloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  Enhanced block allocation by Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include "ext2.h"
//#include <linux/quotaops.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/buffer_head.h>
//#include <linux/capability.h>

/*
 * balloc.c contains the blocks allocation and deallocation routines
 */

/*
 * The free blocks are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.  The descriptors are loaded in memory
 * when a file system is mounted (see ext2_fill_super).
 */

struct ext2_group_desc *
ext2_get_group_desc(struct super_block * sb,
                    unsigned int block_group,
                    struct buffer_head ** bh)
{
    unsigned long group_desc;
    unsigned long offset;
    struct ext2_group_desc *desc;
    struct ext2_sb_info *sbi = EXT2_SB(sb);

    if (block_group >= sbi->s_groups_count) {
        WARN(1, "block_group >= groups_count - "
             "block_group = %d, groups_count = %lu",
             block_group, sbi->s_groups_count);

        return NULL;
    }

    group_desc = block_group >> EXT2_DESC_PER_BLOCK_BITS(sb);
    offset = block_group & (EXT2_DESC_PER_BLOCK(sb) - 1);
    if (!sbi->s_group_desc[group_desc]) {
        WARN(1, "Group descriptor not loaded - "
             "block_group = %d, group_desc = %lu, desc = %lu",
              block_group, group_desc, offset);
        return NULL;
    }

    desc = (struct ext2_group_desc *) sbi->s_group_desc[group_desc]->b_data;
    if (bh)
        *bh = sbi->s_group_desc[group_desc];
    return desc + offset;
}

unsigned long ext2_count_free_blocks(struct super_block * sb)
{
    struct ext2_group_desc *desc;
    unsigned long desc_count = 0;
    int i;

    for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
        desc = ext2_get_group_desc(sb, i, NULL);
        if (!desc)
            continue;
        desc_count += le16_to_cpu(desc->bg_free_blocks_count);
    }
    return desc_count;
}

/*
 * ext2_rsv_window_add() -- Insert a window to the block reservation rb tree.
 * @sb:         super block
 * @rsv:        reservation window to add
 *
 * Must be called with rsv_lock held.
 */
void ext2_rsv_window_add(struct super_block *sb,
                         struct ext2_reserve_window_node *rsv)
{
    struct rb_root *root = &EXT2_SB(sb)->s_rsv_window_root;
    struct rb_node *node = &rsv->rsv_node;
    ext2_fsblk_t start = rsv->rsv_start;

    struct rb_node **p = &root->rb_node;
    struct rb_node *parent = NULL;
    struct ext2_reserve_window_node *this;

    while (*p)
    {
        parent = *p;
        this = rb_entry(parent, struct ext2_reserve_window_node, rsv_node);

        if (start < this->rsv_start)
            p = &(*p)->rb_left;
        else if (start > this->rsv_end)
            p = &(*p)->rb_right;
        else {
            //rsv_window_dump(root, 1);
            BUG();
        }
    }

    rb_link_node(node, parent, p);
    rb_insert_color(node, root);
}
