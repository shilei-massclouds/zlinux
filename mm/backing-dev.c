// SPDX-License-Identifier: GPL-2.0-only

#include <linux/wait.h>
#include <linux/rbtree.h>
#include <linux/kthread.h>
#include <linux/backing-dev.h>
#if 0
#include <linux/blk-cgroup.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#endif
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/device.h>

struct backing_dev_info noop_backing_dev_info;
EXPORT_SYMBOL_GPL(noop_backing_dev_info);

static struct class *bdi_class;
static const char *bdi_unknown_name = "(unknown)";

static int bdi_init(struct backing_dev_info *bdi)
{
    int ret;

    bdi->dev = NULL;

    kref_init(&bdi->refcnt);
    bdi->min_ratio = 0;
    bdi->max_ratio = 100;
    //bdi->max_prop_frac = FPROP_FRAC_BASE;
    INIT_LIST_HEAD(&bdi->bdi_list);
    INIT_LIST_HEAD(&bdi->wb_list);
#if 0
    init_waitqueue_head(&bdi->wb_waitq);

    ret = cgwb_bdi_init(bdi);
#endif

    return ret;
}

struct backing_dev_info *bdi_alloc(int node_id)
{
    struct backing_dev_info *bdi;

    bdi = kzalloc_node(sizeof(*bdi), GFP_KERNEL, node_id);
    if (!bdi)
        return NULL;

    if (bdi_init(bdi)) {
        kfree(bdi);
        return NULL;
    }
    bdi->capabilities = BDI_CAP_WRITEBACK | BDI_CAP_WRITEBACK_ACCT;
    bdi->ra_pages = VM_READAHEAD_PAGES;
    bdi->io_pages = VM_READAHEAD_PAGES;
    //timer_setup(&bdi->laptop_mode_wb_timer, laptop_mode_timer_fn, 0);
    return bdi;
}
EXPORT_SYMBOL(bdi_alloc);
