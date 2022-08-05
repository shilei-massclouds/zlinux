// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext2/ialloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  BSD ufs-inspired inode and directory allocation by
 *  Stephen Tweedie (sct@dcs.ed.ac.uk), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

//#include <linux/quotaops.h>
#include <linux/sched.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>
#include <linux/random.h>
#include "ext2.h"
#if 0
#include "xattr.h"
#include "acl.h"
#endif

/*
 * ialloc.c contains the inodes allocation and deallocation routines
 */

/*
 * The free inodes are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.
 */

unsigned long ext2_count_free_inodes(struct super_block *sb)
{
    struct ext2_group_desc *desc;
    unsigned long desc_count = 0;
    int i;

    for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
        desc = ext2_get_group_desc (sb, i, NULL);
        if (!desc)
            continue;
        desc_count += le16_to_cpu(desc->bg_free_inodes_count);
    }
    return desc_count;
}


/* Called at mount-time, super-block is locked */
unsigned long ext2_count_dirs(struct super_block *sb)
{
    unsigned long count = 0;
    int i;

    for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
        struct ext2_group_desc *gdp = ext2_get_group_desc(sb, i, NULL);
        if (!gdp)
            continue;
        count += le16_to_cpu(gdp->bg_used_dirs_count);
    }
    return count;
}
