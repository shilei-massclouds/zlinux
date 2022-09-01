// SPDX-License-Identifier: GPL-2.0-only
/*
 * fs/fs-writeback.c
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * Contains all the functions related to writing back and waiting
 * upon dirty inodes against superblocks, and writing back dirty
 * pages against inodes.  ie: data writeback.  Writeout of the
 * inode itself is not handled here.
 *
 * 10Apr2002    Andrew Morton
 *      Split out of fs/inode.c
 *      Additions for address_space-based writeback
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/kthread.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
//#include <linux/tracepoint.h>
#include <linux/device.h>
#include <linux/memcontrol.h>
#include "internal.h"

/**
 * __mark_inode_dirty - internal function to mark an inode dirty
 *
 * @inode: inode to mark
 * @flags: what kind of dirty, e.g. I_DIRTY_SYNC.  This can be a combination of
 *     multiple I_DIRTY_* flags, except that I_DIRTY_TIME can't be combined
 *     with I_DIRTY_PAGES.
 *
 * Mark an inode as dirty.  We notify the filesystem, then update the inode's
 * dirty flags.  Then, if needed we add the inode to the appropriate dirty list.
 *
 * Most callers should use mark_inode_dirty() or mark_inode_dirty_sync()
 * instead of calling this directly.
 *
 * CAREFUL!  We only add the inode to the dirty list if it is hashed or if it
 * refers to a blockdev.  Unhashed inodes will never be added to the dirty list
 * even if they are later hashed, as they will have been marked dirty already.
 *
 * In short, ensure you hash any inodes _before_ you start marking them dirty.
 *
 * Note that for blockdevs, inode->dirtied_when represents the dirtying time of
 * the block-special inode (/dev/hda1) itself.  And the ->dirtied_when field of
 * the kernel-internal blockdev inode represents the dirtying time of the
 * blockdev's pages.  This is why for I_DIRTY_PAGES we always use
 * page->mapping->host, so the page-dirtying time is recorded in the internal
 * blockdev inode.
 */
void __mark_inode_dirty(struct inode *inode, int flags)
{
    panic("%s: END!\n", __func__);
}

/**
 * write_inode_now  -   write an inode to disk
 * @inode: inode to write to disk
 * @sync: whether the write should be synchronous or not
 *
 * This function commits an inode to disk immediately if it is dirty. This is
 * primarily needed by knfsd.
 *
 * The caller must either have a ref on the inode or must have set I_WILL_FREE.
 */
int write_inode_now(struct inode *inode, int sync)
{
    panic("%s: END!\n", __func__);
}

/*
 * Wait for writeback on an inode to complete. Called with i_lock held.
 * Caller must make sure inode cannot go away when we drop i_lock.
 */
static void __inode_wait_for_writeback(struct inode *inode)
    __releases(inode->i_lock)
    __acquires(inode->i_lock)
{
    DEFINE_WAIT_BIT(wq, &inode->i_state, __I_SYNC);
    wait_queue_head_t *wqh;

    wqh = bit_waitqueue(&inode->i_state, __I_SYNC);
    while (inode->i_state & I_SYNC) {
        spin_unlock(&inode->i_lock);
        __wait_on_bit(wqh, &wq, bit_wait, TASK_UNINTERRUPTIBLE);
        spin_lock(&inode->i_lock);
    }
}

/*
 * Wait for writeback on an inode to complete. Caller must have inode pinned.
 */
void inode_wait_for_writeback(struct inode *inode)
{
    spin_lock(&inode->i_lock);
    __inode_wait_for_writeback(inode);
    spin_unlock(&inode->i_lock);
}

/*
 * Wakeup the flusher threads to start writeback of all currently dirty pages
 */
void wakeup_flusher_threads(enum wb_reason reason)
{
    panic("%s: END!\n", __func__);
}
