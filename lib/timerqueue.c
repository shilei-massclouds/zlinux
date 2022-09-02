// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Generic Timer-queue
 *
 *  Manages a simple queue of timers, ordered by expiration time.
 *  Uses rbtrees for quick list adds and expiration.
 *
 *  NOTE: All of the following functions need to be serialized
 *  to avoid races. No locking is done by this library code.
 */

#include <linux/bug.h>
#include <linux/timerqueue.h>
#include <linux/rbtree.h>
#include <linux/export.h>

#define __node_2_tq(_n) \
    rb_entry((_n), struct timerqueue_node, node)

static inline
bool __timerqueue_less(struct rb_node *a, const struct rb_node *b)
{
    return __node_2_tq(a)->expires < __node_2_tq(b)->expires;
}

/**
 * timerqueue_add - Adds timer to timerqueue.
 *
 * @head: head of timerqueue
 * @node: timer node to be added
 *
 * Adds the timer node to the timerqueue, sorted by the node's expires
 * value. Returns true if the newly added timer is the first expiring timer in
 * the queue.
 */
bool timerqueue_add(struct timerqueue_head *head,
                    struct timerqueue_node *node)
{
    /* Make sure we don't add nodes that are already added */
    WARN_ON_ONCE(!RB_EMPTY_NODE(&node->node));

    return rb_add_cached(&node->node, &head->rb_root, __timerqueue_less);
}
EXPORT_SYMBOL_GPL(timerqueue_add);
