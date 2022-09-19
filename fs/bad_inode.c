// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/bad_inode.c
 *
 *  Copyright (C) 1997, Stephen Tweedie
 *
 *  Provide stub functions for unreadable inodes
 *
 *  Fabian Frederick : August 2003 - All file operations assigned to EIO
 */

#include <linux/fs.h>
#include <linux/export.h>
#include <linux/stat.h>
//#include <linux/time.h>
#include <linux/namei.h>
//#include <linux/poll.h>
//#include <linux/fiemap.h>

/**
 *  make_bad_inode - mark an inode bad due to an I/O error
 *  @inode: Inode to mark bad
 *
 *  When an inode cannot be read due to a media or remote network
 *  failure this function makes the inode "bad" and causes I/O operations
 *  on it to fail from this point on.
 */

void make_bad_inode(struct inode *inode)
{
    remove_inode_hash(inode);

    inode->i_mode = S_IFREG;
    inode->i_atime = inode->i_mtime = inode->i_ctime =
        current_time(inode);
#if 0
    inode->i_op = &bad_inode_ops;
    inode->i_opflags &= ~IOP_XATTR;
    inode->i_fop = &bad_file_ops;
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(make_bad_inode);

/**
 * iget_failed - Mark an under-construction inode as dead and release it
 * @inode: The inode to discard
 *
 * Mark an under-construction inode as dead and release it.
 */
void iget_failed(struct inode *inode)
{
    make_bad_inode(inode);
    unlock_new_inode(inode);
    iput(inode);
}
EXPORT_SYMBOL(iget_failed);
