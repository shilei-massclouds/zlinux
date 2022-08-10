// SPDX-License-Identifier: GPL-2.0-only

#include <linux/wait.h>
#include <linux/rbtree.h>
#include <linux/kthread.h>
#include <linux/backing-dev.h>
#if 0
#include <linux/blk-cgroup.h>
#include <linux/freezer.h>
#endif
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/device.h>
#include <linux/blkdev.h>

struct backing_dev_info noop_backing_dev_info;
EXPORT_SYMBOL_GPL(noop_backing_dev_info);

static struct class *bdi_class;
static const char *bdi_unknown_name = "(unknown)";

/*
 * bdi_lock protects bdi_tree and updates to bdi_list. bdi_list has RCU
 * reader side locking.
 */
DEFINE_SPINLOCK(bdi_lock);
static u64 bdi_id_cursor;
static struct rb_root bdi_tree = RB_ROOT;
LIST_HEAD(bdi_list);

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

static void cgwb_bdi_register(struct backing_dev_info *bdi)
{
    list_add_tail_rcu(&bdi->wb.bdi_node, &bdi->wb_list);
}

static struct rb_node **bdi_lookup_rb_node(u64 id, struct rb_node **parentp)
{
    struct rb_node **p = &bdi_tree.rb_node;
    struct rb_node *parent = NULL;
    struct backing_dev_info *bdi;

    while (*p) {
        parent = *p;
        bdi = rb_entry(parent, struct backing_dev_info, rb_node);

        if (bdi->id > id)
            p = &(*p)->rb_left;
        else if (bdi->id < id)
            p = &(*p)->rb_right;
        else
            break;
    }

    if (parentp)
        *parentp = parent;
    return p;
}

int bdi_register_va(struct backing_dev_info *bdi, const char *fmt, va_list args)
{
    struct device *dev;
    struct rb_node *parent, **p;

    if (bdi->dev)   /* The driver needs to use separate queues per device */
        return 0;

    vsnprintf(bdi->dev_name, sizeof(bdi->dev_name), fmt, args);
    dev = device_create(bdi_class, NULL, MKDEV(0, 0), bdi, bdi->dev_name);
    if (IS_ERR(dev))
        return PTR_ERR(dev);

    cgwb_bdi_register(bdi);
    bdi->dev = dev;

    set_bit(WB_registered, &bdi->wb.state);

    spin_lock_bh(&bdi_lock);

    bdi->id = ++bdi_id_cursor;

    p = bdi_lookup_rb_node(bdi->id, &parent);
    rb_link_node(&bdi->rb_node, parent, p);
    rb_insert_color(&bdi->rb_node, &bdi_tree);

    list_add_tail_rcu(&bdi->bdi_list, &bdi_list);

    spin_unlock_bh(&bdi_lock);
    return 0;
}

void bdi_set_owner(struct backing_dev_info *bdi, struct device *owner)
{
    WARN_ON_ONCE(bdi->owner);
    bdi->owner = owner;
    get_device(owner);
}

int bdi_register(struct backing_dev_info *bdi, const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = bdi_register_va(bdi, fmt, args);
    va_end(args);
    return ret;
}
EXPORT_SYMBOL(bdi_register);

static __init int bdi_class_init(void)
{
    bdi_class = class_create(THIS_MODULE, "bdi");
    if (IS_ERR(bdi_class))
        return PTR_ERR(bdi_class);

#if 0
    bdi_class->dev_groups = bdi_dev_groups;
#endif

    return 0;
}
postcore_initcall(bdi_class_init);

struct backing_dev_info *inode_to_bdi(struct inode *inode)
{
    struct super_block *sb;

    if (!inode)
        return &noop_backing_dev_info;

    sb = inode->i_sb;
    if (sb_is_blkdev_sb(sb))
        return I_BDEV(inode)->bd_disk->bdi;
    return sb->s_bdi;
}
EXPORT_SYMBOL(inode_to_bdi);

void bdi_unregister(struct backing_dev_info *bdi)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(bdi_unregister);

static void release_bdi(struct kref *ref)
{
#if 0
    struct backing_dev_info *bdi =
        container_of(ref, struct backing_dev_info, refcnt);

    WARN_ON_ONCE(test_bit(WB_registered, &bdi->wb.state));
    WARN_ON_ONCE(bdi->dev);
    wb_exit(&bdi->wb);
    kfree(bdi);
#endif
    panic("%s: END!\n", __func__);
}

void bdi_put(struct backing_dev_info *bdi)
{
    kref_put(&bdi->refcnt, release_bdi);
}
EXPORT_SYMBOL(bdi_put);
