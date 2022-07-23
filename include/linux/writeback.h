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
#include <linux/backing-dev-defs.h>
#include <linux/blk_types.h>
*/

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

#endif  /* WRITEBACK_H */
