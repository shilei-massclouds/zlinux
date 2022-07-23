/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BACKING_DEV_DEFS_H
#define __LINUX_BACKING_DEV_DEFS_H

#include <linux/list.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/percpu_counter.h>
#if 0
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
struct backing_dev_info;

/*
 * Bits in bdi_writeback.state
 */
enum wb_state {
    WB_registered,      /* bdi_register() was done */
    WB_writeback_running,   /* Writeback is in progress */
    WB_has_dirty_io,    /* Dirty inodes on ->b_{dirty|io|more_io} */
    WB_start_all,       /* nr_pages == 0 (all) work pending */
};

enum wb_stat_item {
    WB_RECLAIMABLE,
    WB_WRITEBACK,
    WB_DIRTIED,
    WB_WRITTEN,
    NR_WB_STAT_ITEMS
};

/*
 * why some writeback work was initiated
 */
enum wb_reason {
    WB_REASON_BACKGROUND,
    WB_REASON_VMSCAN,
    WB_REASON_SYNC,
    WB_REASON_PERIODIC,
    WB_REASON_LAPTOP_TIMER,
    WB_REASON_FS_FREE_SPACE,
    /*
     * There is no bdi forker thread any more and works are done
     * by emergency worker, however, this is TPs userland visible
     * and we'll be exposing exactly the same information,
     * so it has a mismatch name.
     */
    WB_REASON_FORKER_THREAD,
    WB_REASON_FOREIGN_FLUSH,

    WB_REASON_MAX,
};

/*
 * Each wb (bdi_writeback) can perform writeback operations, is measured
 * and throttled, independently.  Without cgroup writeback, each bdi
 * (bdi_writeback) is served by its embedded bdi->wb.
 *
 * On the default hierarchy, blkcg implicitly enables memcg.  This allows
 * using memcg's page ownership for attributing writeback IOs, and every
 * memcg - blkcg combination can be served by its own wb by assigning a
 * dedicated wb to each memcg, which enables isolation across different
 * cgroups and propagation of IO back pressure down from the IO layer upto
 * the tasks which are generating the dirty pages to be written back.
 *
 * A cgroup wb is indexed on its bdi by the ID of the associated memcg,
 * refcounted with the number of inodes attached to it, and pins the memcg
 * and the corresponding blkcg.  As the corresponding blkcg for a memcg may
 * change as blkcg is disabled and enabled higher up in the hierarchy, a wb
 * is tested for blkcg after lookup and removed from index on mismatch so
 * that a new wb for the combination can be created.
 *
 * Each bdi_writeback that is not embedded into the backing_dev_info must hold
 * a reference to the parent backing_dev_info.  See cgwb_create() for details.
 */
struct bdi_writeback {
    struct backing_dev_info *bdi;   /* our parent bdi */

    unsigned long state;        /* Always use atomic bitops on this */
    unsigned long last_old_flush;   /* last old data flush */

    struct list_head b_dirty;   /* dirty inodes */
    struct list_head b_io;      /* parked for writeback */
    struct list_head b_more_io; /* parked for more writeback */
    struct list_head b_dirty_time;  /* time stamps are dirty */
    spinlock_t list_lock;       /* protects the b_* lists */

    atomic_t writeback_inodes;  /* number of inodes under writeback */
    struct percpu_counter stat[NR_WB_STAT_ITEMS];

    unsigned long congested;    /* WB_[a]sync_congested flags */

    unsigned long bw_time_stamp;    /* last time write bw is updated */
    unsigned long dirtied_stamp;
    unsigned long written_stamp;    /* pages written at bw_time_stamp */
    unsigned long write_bandwidth;  /* the estimated write bandwidth */
    unsigned long avg_write_bandwidth; /* further smoothed write bw, > 0 */

    /*
     * The base dirty throttle rate, re-calculated on every 200ms.
     * All the bdi tasks' dirty rate will be curbed under it.
     * @dirty_ratelimit tracks the estimated @balanced_dirty_ratelimit
     * in small steps and is much more smooth/stable than the latter.
     */
    unsigned long dirty_ratelimit;
    unsigned long balanced_dirty_ratelimit;

    //struct fprop_local_percpu completions;
    int dirty_exceeded;
    enum wb_reason start_all_reason;

    spinlock_t work_lock;       /* protects work_list & dwork scheduling */
    struct list_head work_list;
#if 0
    struct delayed_work dwork;  /* work item used for writeback */
    struct delayed_work bw_dwork;   /* work item used for bandwidth estimate */
#endif

    unsigned long dirty_sleep;  /* last wait */

    struct list_head bdi_node;  /* anchored at bdi->wb_list */
};

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

    struct bdi_writeback wb;  /* the root writeback info for this bdi */
    struct list_head wb_list; /* list of all wbs */
    //wait_queue_head_t wb_waitq;

    struct device *dev;
    char dev_name[64];
    struct device *owner;

    //struct timer_list laptop_mode_wb_timer;
};

#endif  /* __LINUX_BACKING_DEV_DEFS_H */
