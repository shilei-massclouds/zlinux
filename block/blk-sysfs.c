// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to sysfs handling
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
//#include <linux/blktrace_api.h>
#include <linux/blk-mq.h>
//#include <linux/debugfs.h>

#include "blk.h"
#include "blk-mq.h"
//#include "blk-mq-debugfs.h"
#include "blk-mq-sched.h"
#if 0
#include "blk-wbt.h"
#include "blk-cgroup.h"
#include "blk-throttle.h"
#endif

static ssize_t
queue_attr_show(struct kobject *kobj, struct attribute *attr,
                char *page)
{
    panic("%s: END!\n", __func__);
}

static ssize_t
queue_attr_store(struct kobject *kobj, struct attribute *attr,
                 const char *page, size_t length)
{
    panic("%s: END!\n", __func__);
}

static const struct sysfs_ops queue_sysfs_ops = {
    .show   = queue_attr_show,
    .store  = queue_attr_store,
};

/**
 * blk_release_queue - releases all allocated resources of the request_queue
 * @kobj: pointer to a kobject, whose container is a request_queue
 *
 * This function releases all allocated resources of the request queue.
 *
 * The struct request_queue refcount is incremented with blk_get_queue() and
 * decremented with blk_put_queue(). Once the refcount reaches 0 this function
 * is called.
 *
 * For drivers that have a request_queue on a gendisk and added with
 * __device_add_disk() the refcount to request_queue will reach 0 with
 * the last put_disk() called by the driver. For drivers which don't use
 * __device_add_disk() this happens with blk_cleanup_queue().
 *
 * Drivers exist which depend on the release of the request_queue to be
 * synchronous, it should not be deferred.
 *
 * Context: can sleep
 */
static void blk_release_queue(struct kobject *kobj)
{
    panic("%s: END!\n", __func__);
}

struct kobj_type blk_queue_ktype = {
    .sysfs_ops  = &queue_sysfs_ops,
    .release    = blk_release_queue,
};
