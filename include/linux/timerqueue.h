/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIMERQUEUE_H
#define _LINUX_TIMERQUEUE_H

#include <linux/rbtree.h>
#include <linux/ktime.h>

struct timerqueue_node {
    struct rb_node node;
    ktime_t expires;
};

struct timerqueue_head {
    struct rb_root_cached rb_root;
};

static inline void timerqueue_init(struct timerqueue_node *node)
{
    RB_CLEAR_NODE(&node->node);
}

static inline void timerqueue_init_head(struct timerqueue_head *head)
{
    head->rb_root = RB_ROOT_CACHED;
}

extern bool timerqueue_add(struct timerqueue_head *head,
                           struct timerqueue_node *node);
extern bool timerqueue_del(struct timerqueue_head *head,
                           struct timerqueue_node *node);
extern struct timerqueue_node *
timerqueue_iterate_next(struct timerqueue_node *node);

#endif /* _LINUX_TIMERQUEUE_H */
