/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/writeback.h
 */
#ifndef WRITEBACK_H
#define WRITEBACK_H

#include <linux/sched.h>
#include <linux/fs.h>
/*
#include <linux/workqueue.h>
#include <linux/flex_proportions.h>
*/
#include <linux/backing-dev-defs.h>
#include <linux/blk_types.h>

/*
 * fs/fs-writeback.c
 */
enum writeback_sync_modes {
    WB_SYNC_NONE,   /* Don't wait on anything */
    WB_SYNC_ALL,    /* Wait on every mapping */
};

/*
 * A control structure which tells the writeback code what to do.  These are
 * always on the stack, and hence need no locking.  They are always initialised
 * in a manner such that unspecified fields are set to zero.
 */
struct writeback_control {
    long nr_to_write;       /* Write this many pages, and decrement
                       this for each page written */
    long pages_skipped;     /* Pages which were not written */

    /*
     * For a_ops->writepages(): if start or end are non-zero then this is
     * a hint that the filesystem need only write out the pages inside that
     * byterange.  The byte at `end' is included in the writeout request.
     */
    loff_t range_start;
    loff_t range_end;

    enum writeback_sync_modes sync_mode;

    unsigned for_kupdate:1;     /* A kupdate writeback */
    unsigned for_background:1;  /* A background writeback */
    unsigned tagged_writepages:1;   /* tag-and-write to avoid livelock */
    unsigned for_reclaim:1;     /* Invoked from the page allocator */
    unsigned range_cyclic:1;    /* range_start is cyclic */
    unsigned for_sync:1;        /* sync(2) WB_SYNC_ALL writeback */
    unsigned unpinned_fscache_wb:1; /* Cleared I_PINNING_FSCACHE_WB */

    /*
     * When writeback IOs are bounced through async layers, only the
     * initial synchronous phase should be accounted towards inode
     * cgroup ownership arbitration to avoid confusion.  Later stages
     * can set the following flag to disable the accounting.
     */
    unsigned no_cgroup_owner:1;

    unsigned punt_to_cgroup:1;  /* cgrp punting, see __REQ_CGROUP_PUNT */
};

/*
 * mm/page-writeback.c
 */
bool node_dirty_ok(struct pglist_data *pgdat);

/* writeback.h requires fs.h; it, too, is not included from here. */
static inline void wait_on_inode(struct inode *inode)
{
    might_sleep();
#if 0
    wait_on_bit(&inode->i_state, __I_NEW, TASK_UNINTERRUPTIBLE);
#endif
    panic("%s: NO implementation!\n", __func__);
}

/**
 * inode_detach_wb - disassociate an inode from its wb
 * @inode: inode of interest
 *
 * @inode is being freed.  Detach from its wb.
 */
static inline void inode_detach_wb(struct inode *inode)
{
}

void inode_wait_for_writeback(struct inode *inode);

extern int laptop_mode;

#endif  /* WRITEBACK_H */
