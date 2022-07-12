/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BACKING_DEV_DEFS_H
#define __LINUX_BACKING_DEV_DEFS_H

#include <linux/list.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#if 0
#include <linux/percpu_counter.h>
#include <linux/percpu-refcount.h>
#include <linux/flex_proportions.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#endif
#include <linux/kref.h>
#include <linux/refcount.h>

struct page;
struct device;
struct dentry;

struct backing_dev_info {
    u64 id;
    struct rb_node rb_node; /* keyed by ->id */
    struct list_head bdi_list;
    unsigned long ra_pages; /* max readahead in PAGE_SIZE units */
    unsigned long io_pages; /* max allowed IO size */

    struct kref refcnt; /* Reference counter for the structure */
    unsigned int capabilities; /* Device capabilities */
    unsigned int min_ratio;
    unsigned int max_ratio, max_prop_frac;

    /*
     * Sum of avg_write_bw of wbs with dirty inodes.  > 0 if there are
     * any dirty wbs, which is depended upon by bdi_has_dirty().
     */
    atomic_long_t tot_write_bandwidth;

    //struct bdi_writeback wb;  /* the root writeback info for this bdi */
    struct list_head wb_list; /* list of all wbs */
    //wait_queue_head_t wb_waitq;

    struct device *dev;
    char dev_name[64];
    struct device *owner;

    //struct timer_list laptop_mode_wb_timer;
};

#endif  /* __LINUX_BACKING_DEV_DEFS_H */
