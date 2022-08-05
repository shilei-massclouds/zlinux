// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext2/inode.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Goal-directed block allocation by Stephen Tweedie
 *  (sct@dcs.ed.ac.uk), 1993, 1998
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *  (jj@sunsite.ms.mff.cuni.cz)
 *
 *  Assorted race fixes, rewrite of ext2_get_block() by Al Viro, 2000
 */

#if 0
#include <linux/time.h>
#include <linux/highuid.h>
#include <linux/dax.h>
#include <linux/quotaops.h>
#endif
#include <linux/fs.h>
#include <linux/mpage.h>
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#if 0
#include <linux/fiemap.h>
#include <linux/iomap.h>
#include <linux/uio.h>
#endif
#include <linux/namei.h>
#include "ext2.h"
#if 0
#include "acl.h"
#include "xattr.h"
#endif

static int ext2_readpage(struct file *file, struct page *page)
{
    return mpage_readpage(page, ext2_get_block);
}

static void ext2_readahead(struct readahead_control *rac)
{
    panic("%s: END!\n", __func__);
    //mpage_readahead(rac, ext2_get_block);
}

static int ext2_writepage(struct page *page, struct writeback_control *wbc)
{
    panic("%s: END!\n", __func__);
    //return block_write_full_page(page, ext2_get_block, wbc);
}

static int
ext2_write_begin(struct file *file, struct address_space *mapping,
                 loff_t pos, unsigned len, unsigned flags,
                 struct page **pagep, void **fsdata)
{
    panic("%s: END!\n", __func__);
}

static int ext2_write_end(struct file *file, struct address_space *mapping,
                          loff_t pos, unsigned len, unsigned copied,
                          struct page *page, void *fsdata)
{
    panic("%s: END!\n", __func__);
}

static sector_t ext2_bmap(struct address_space *mapping, sector_t block)
{
    panic("%s: END!\n", __func__);
    //return generic_block_bmap(mapping,block,ext2_get_block);
}

static ssize_t
ext2_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
    panic("%s: END!\n", __func__);
}

static int
ext2_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
    panic("%s: END!\n", __func__);
    //return mpage_writepages(mapping, wbc, ext2_get_block);
}

const struct address_space_operations ext2_aops = {
    .dirty_folio        = block_dirty_folio,
    .invalidate_folio   = block_invalidate_folio,
    .readpage           = ext2_readpage,
    .readahead          = ext2_readahead,
    .writepage          = ext2_writepage,
    .write_begin        = ext2_write_begin,
    .write_end          = ext2_write_end,
    .bmap               = ext2_bmap,
    .direct_IO          = ext2_direct_IO,
    .writepages         = ext2_writepages,
    .migratepage        = buffer_migrate_page,
    .is_partially_uptodate  = block_is_partially_uptodate,
    .error_remove_page  = generic_error_remove_page,
};

static int ext2_nobh_writepage(struct page *page,
                               struct writeback_control *wbc)
{
    panic("%s: END!\n", __func__);
    //return nobh_writepage(page, ext2_get_block, wbc);
}

static int
ext2_nobh_write_begin(struct file *file, struct address_space *mapping,
                      loff_t pos, unsigned len, unsigned flags,
                      struct page **pagep, void **fsdata)
{
    panic("%s: END!\n", __func__);
}

const struct address_space_operations ext2_nobh_aops = {
    .dirty_folio        = block_dirty_folio,
    .invalidate_folio   = block_invalidate_folio,
    .readpage           = ext2_readpage,
    .readahead          = ext2_readahead,
    .writepage          = ext2_nobh_writepage,
    .write_begin        = ext2_nobh_write_begin,
    .write_end          = nobh_write_end,
    .bmap               = ext2_bmap,
    .direct_IO          = ext2_direct_IO,
    .writepages         = ext2_writepages,
    .migratepage        = buffer_migrate_page,
    .error_remove_page  = generic_error_remove_page,
};

static struct ext2_inode *
ext2_get_inode(struct super_block *sb, ino_t ino, struct buffer_head **p)
{
    struct buffer_head *bh;
    unsigned long block_group;
    unsigned long block;
    unsigned long offset;
    struct ext2_group_desc *gdp;

    *p = NULL;
    if ((ino != EXT2_ROOT_INO && ino < EXT2_FIRST_INO(sb)) ||
        ino > le32_to_cpu(EXT2_SB(sb)->s_es->s_inodes_count))
        goto Einval;

    block_group = (ino - 1) / EXT2_INODES_PER_GROUP(sb);
    gdp = ext2_get_group_desc(sb, block_group, NULL);
    if (!gdp)
        goto Egdp;
    /*
     * Figure out the offset within the block group inode table
     */
    offset = ((ino - 1) % EXT2_INODES_PER_GROUP(sb)) * EXT2_INODE_SIZE(sb);
    block = le32_to_cpu(gdp->bg_inode_table) +
        (offset >> EXT2_BLOCK_SIZE_BITS(sb));
    if (!(bh = sb_bread(sb, block)))
        goto Eio;

    *p = bh;
    offset &= (EXT2_BLOCK_SIZE(sb) - 1);
    return (struct ext2_inode *) (bh->b_data + offset);

 Einval:
    ext2_error(sb, "ext2_get_inode", "bad inode number: %lu",
               (unsigned long) ino);
    return ERR_PTR(-EINVAL);
 Eio:
    ext2_error(sb, "ext2_get_inode",
               "unable to read inode block - inode=%lu, block=%lu",
               (unsigned long) ino, block);
 Egdp:
    return ERR_PTR(-EIO);
}

void ext2_set_inode_flags(struct inode *inode)
{
    unsigned int flags = EXT2_I(inode)->i_flags;

    inode->i_flags &= ~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME |
                        S_DIRSYNC | S_DAX);
    if (flags & EXT2_SYNC_FL)
        inode->i_flags |= S_SYNC;
    if (flags & EXT2_APPEND_FL)
        inode->i_flags |= S_APPEND;
    if (flags & EXT2_IMMUTABLE_FL)
        inode->i_flags |= S_IMMUTABLE;
    if (flags & EXT2_NOATIME_FL)
        inode->i_flags |= S_NOATIME;
    if (flags & EXT2_DIRSYNC_FL)
        inode->i_flags |= S_DIRSYNC;
    if (test_opt(inode->i_sb, DAX) && S_ISREG(inode->i_mode))
        inode->i_flags |= S_DAX;
}

struct inode *ext2_iget(struct super_block *sb, unsigned long ino)
{
    struct ext2_inode_info *ei;
    struct buffer_head *bh = NULL;
    struct ext2_inode *raw_inode;
    struct inode *inode;
    long ret = -EIO;
    int n;
    uid_t i_uid;
    gid_t i_gid;

    inode = iget_locked(sb, ino);
    if (!inode)
        return ERR_PTR(-ENOMEM);
    if (!(inode->i_state & I_NEW))
        return inode;

    ei = EXT2_I(inode);
    ei->i_block_alloc_info = NULL;

    raw_inode = ext2_get_inode(inode->i_sb, ino, &bh);
    if (IS_ERR(raw_inode)) {
        ret = PTR_ERR(raw_inode);
        goto bad_inode;
    }

    inode->i_mode = le16_to_cpu(raw_inode->i_mode);
    i_uid = (uid_t)le16_to_cpu(raw_inode->i_uid_low);
    i_gid = (gid_t)le16_to_cpu(raw_inode->i_gid_low);
    if (!(test_opt (inode->i_sb, NO_UID32))) {
        i_uid |= le16_to_cpu(raw_inode->i_uid_high) << 16;
        i_gid |= le16_to_cpu(raw_inode->i_gid_high) << 16;
    }
#if 0
    i_uid_write(inode, i_uid);
    i_gid_write(inode, i_gid);
    set_nlink(inode, le16_to_cpu(raw_inode->i_links_count));
#endif
    inode->i_size = le32_to_cpu(raw_inode->i_size);
#if 0
    inode->i_atime.tv_sec = (signed)le32_to_cpu(raw_inode->i_atime);
    inode->i_ctime.tv_sec = (signed)le32_to_cpu(raw_inode->i_ctime);
    inode->i_mtime.tv_sec = (signed)le32_to_cpu(raw_inode->i_mtime);
    inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
        inode->i_ctime.tv_nsec = 0;
#endif
    ei->i_dtime = le32_to_cpu(raw_inode->i_dtime);
    /* We now have enough fields to check if the inode was active or not.
     * This is needed because nfsd might try to access dead inodes
     * the test is that same one that e2fsck uses
     * NeilBrown 1999oct15
     */
    if (inode->i_nlink == 0 && (inode->i_mode == 0 || ei->i_dtime)) {
        /* this inode is deleted */
        ret = -ESTALE;
        goto bad_inode;
    }
    inode->i_blocks = le32_to_cpu(raw_inode->i_blocks);
    ei->i_flags = le32_to_cpu(raw_inode->i_flags);
    ext2_set_inode_flags(inode);
    ei->i_faddr = le32_to_cpu(raw_inode->i_faddr);
    ei->i_frag_no = raw_inode->i_frag;
    ei->i_frag_size = raw_inode->i_fsize;
    ei->i_file_acl = le32_to_cpu(raw_inode->i_file_acl);
    ei->i_dir_acl = 0;

#if 0
    if (ei->i_file_acl &&
        !ext2_data_block_valid(EXT2_SB(sb), ei->i_file_acl, 1)) {
        ext2_error(sb, "ext2_iget", "bad extended attribute block %u",
                   ei->i_file_acl);
        ret = -EFSCORRUPTED;
        goto bad_inode;
    }
#endif

    if (S_ISREG(inode->i_mode))
        inode->i_size |= ((__u64)le32_to_cpu(raw_inode->i_size_high)) << 32;
    else
        ei->i_dir_acl = le32_to_cpu(raw_inode->i_dir_acl);
    if (i_size_read(inode) < 0) {
        ret = -EFSCORRUPTED;
        goto bad_inode;
    }
    ei->i_dtime = 0;
    inode->i_generation = le32_to_cpu(raw_inode->i_generation);
    ei->i_state = 0;
    ei->i_block_group = (ino - 1) / EXT2_INODES_PER_GROUP(inode->i_sb);
    ei->i_dir_start_lookup = 0;

    /*
     * NOTE! The in-memory inode i_data array is in little-endian order
     * even on big-endian machines: we do NOT byteswap the block numbers!
     */
    for (n = 0; n < EXT2_N_BLOCKS; n++)
        ei->i_data[n] = raw_inode->i_block[n];

    if (S_ISREG(inode->i_mode)) {
        //ext2_set_file_ops(inode);
        panic("%s: S_ISREG!\n", __func__);
    } else if (S_ISDIR(inode->i_mode)) {
        inode->i_op = &ext2_dir_inode_operations;
        inode->i_fop = &ext2_dir_operations;
        if (test_opt(inode->i_sb, NOBH))
            inode->i_mapping->a_ops = &ext2_nobh_aops;
        else
            inode->i_mapping->a_ops = &ext2_aops;
    } else if (S_ISLNK(inode->i_mode)) {
#if 0
        if (ext2_inode_is_fast_symlink(inode)) {
            inode->i_link = (char *)ei->i_data;
            inode->i_op = &ext2_fast_symlink_inode_operations;
            nd_terminate_link(ei->i_data, inode->i_size,
                sizeof(ei->i_data) - 1);
        } else {
            inode->i_op = &ext2_symlink_inode_operations;
            inode_nohighmem(inode);
            if (test_opt(inode->i_sb, NOBH))
                inode->i_mapping->a_ops = &ext2_nobh_aops;
            else
                inode->i_mapping->a_ops = &ext2_aops;
        }
#endif
        panic("%s: S_ISLNK!\n", __func__);
    } else {
#if 0
        inode->i_op = &ext2_special_inode_operations;
        if (raw_inode->i_block[0])
            init_special_inode(inode, inode->i_mode,
               old_decode_dev(le32_to_cpu(raw_inode->i_block[0])));
        else
            init_special_inode(inode, inode->i_mode,
               new_decode_dev(le32_to_cpu(raw_inode->i_block[1])));
#endif
        panic("%s: else!\n", __func__);
    }

    brelse(bh);
    unlock_new_inode(inode);
    return inode;

bad_inode:
    brelse(bh);
    iget_failed(inode);
    return ERR_PTR(ret);
}

int ext2_write_inode(struct inode *inode, struct writeback_control *wbc)
{
    panic("%s: END!\n", __func__);
    //return __ext2_write_inode(inode, wbc->sync_mode == WB_SYNC_ALL);
}

/*
 * Called at the last iput() if i_nlink is zero.
 */
void ext2_evict_inode(struct inode * inode)
{
    panic("%s: END!\n", __func__);
}

int ext2_setattr(struct user_namespace *mnt_userns, struct dentry *dentry,
                 struct iattr *iattr)
{
    panic("%s: END!\n", __func__);
}

int ext2_getattr(struct user_namespace *mnt_userns, const struct path *path,
                 struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
    panic("%s: END!\n", __func__);
}

int ext2_get_block(struct inode *inode, sector_t iblock,
                   struct buffer_head *bh_result, int create)
{
    panic("%s: END!\n", __func__);
}
