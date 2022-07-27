// SPDX-License-Identifier: GPL-2.0
/*
 *  Block device elevator/IO-scheduler.
 *
 *  Copyright (C) 2000 Andrea Arcangeli <andrea@suse.de> SuSE
 *
 * 30042000 Jens Axboe <axboe@kernel.dk> :
 *
 * Split the elevator a bit so that it is possible to choose a different
 * one or even write a new "plug in". There are three pieces:
 * - elevator_fn, inserts a new request in the queue list
 * - elevator_merge_fn, decides whether a new buffer can be merged with
 *   an existing request
 * - elevator_dequeue_fn, called when a request is taken off the active list
 *
 * 20082000 Dave Jones <davej@suse.de> :
 * Removed tests for max-bomb-segments, which was breaking elvtune
 *  when run without -bN
 *
 * Jens:
 * - Rework again to work with bio instead of buffer_heads
 * - loose bi_dev comparisons, partition handling is right now
 * - completely modularize elevator setup and teardown
 *
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
//#include <linux/blktrace_api.h>
#include <linux/hash.h>
#include <linux/uaccess.h>
//#include <linux/pm_runtime.h>

#include "elevator.h"
#include "blk.h"
#include "blk-mq-sched.h"
#if 0
#include "blk-pm.h"
#include "blk-wbt.h"
#include "blk-cgroup.h"
#endif

static DEFINE_SPINLOCK(elv_list_lock);
static LIST_HEAD(elv_list);

static inline bool elv_support_iosched(struct request_queue *q)
{
    if (!queue_is_mq(q) ||
        (q->tag_set && (q->tag_set->flags & BLK_MQ_F_NO_SCHED)))
        return false;
    return true;
}

static inline bool elv_support_features(unsigned int elv_features,
                                        unsigned int required_features)
{
    return (required_features & elv_features) == required_features;
}

/**
 * elevator_match - Test an elevator name and features
 * @e: Scheduler to test
 * @name: Elevator name to test
 * @required_features: Features that the elevator must provide
 *
 * Return true if the elevator @e name matches @name and if @e provides all
 * the features specified by @required_features.
 */
static bool elevator_match(const struct elevator_type *e, const char *name,
                           unsigned int required_features)
{
    if (!elv_support_features(e->elevator_features, required_features))
        return false;
    if (!strcmp(e->elevator_name, name))
        return true;
    if (e->elevator_alias && !strcmp(e->elevator_alias, name))
        return true;

    return false;
}

/**
 * elevator_find - Find an elevator
 * @name: Name of the elevator to find
 * @required_features: Features that the elevator must provide
 *
 * Return the first registered scheduler with name @name and supporting the
 * features @required_features and NULL otherwise.
 */
static struct elevator_type *elevator_find(const char *name,
                                           unsigned int required_features)
{
    struct elevator_type *e;

    list_for_each_entry(e, &elv_list, list) {
        if (elevator_match(e, name, required_features))
            return e;
    }

    return NULL;
}

static struct elevator_type *
elevator_get(struct request_queue *q, const char *name, bool try_loading)
{
    struct elevator_type *e;

    spin_lock(&elv_list_lock);

    e = elevator_find(name, q->required_elevator_features);
    if (!e && try_loading) {
        spin_unlock(&elv_list_lock);
        request_module("%s-iosched", name);
        spin_lock(&elv_list_lock);
        e = elevator_find(name, q->required_elevator_features);
    }

    if (e && !try_module_get(e->elevator_owner))
        e = NULL;

    spin_unlock(&elv_list_lock);
    return e;
}

/*
 * For single queue devices, default to using mq-deadline. If we have multiple
 * queues or mq-deadline is not available, default to "none".
 */
static struct elevator_type *elevator_get_default(struct request_queue *q)
{
    if (q->tag_set && q->tag_set->flags & BLK_MQ_F_NO_SCHED_BY_DEFAULT)
        return NULL;

    if (q->nr_hw_queues != 1 && !blk_mq_is_shared_tags(q->tag_set->flags))
        return NULL;

    return elevator_get(q, "mq-deadline", false);
}

/*
 * Get the first elevator providing the features required by the request queue.
 * Default to "none" if no matching elevator is found.
 */
static struct elevator_type *elevator_get_by_features(struct request_queue *q)
{
    panic("%s: END!\n", __func__);
}

/*
 * For a device queue that has no required features, use the default elevator
 * settings. Otherwise, use the first elevator available matching the required
 * features. If no suitable elevator is find or if the chosen elevator
 * initialization fails, fall back to the "none" elevator (no elevator).
 */
void elevator_init_mq(struct request_queue *q)
{
    struct elevator_type *e;
    int err;

    if (!elv_support_iosched(q))
        return;

    WARN_ON_ONCE(blk_queue_registered(q));

    if (unlikely(q->elevator))
        return;

    if (!q->required_elevator_features)
        e = elevator_get_default(q);
    else
        e = elevator_get_by_features(q);
    if (!e)
        return;

    panic("%s: END!\n", __func__);
}
