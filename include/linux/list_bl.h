/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LIST_BL_H
#define _LINUX_LIST_BL_H

#include <linux/list.h>
#include <linux/bit_spinlock.h>

struct hlist_bl_head {
    struct hlist_bl_node *first;
};

struct hlist_bl_node {
    struct hlist_bl_node *next, **pprev;
};

#define INIT_HLIST_BL_HEAD(ptr) \
    ((ptr)->first = NULL)

static inline void INIT_HLIST_BL_NODE(struct hlist_bl_node *h)
{
    h->next = NULL;
    h->pprev = NULL;
}

static inline bool  hlist_bl_unhashed(const struct hlist_bl_node *h)
{
    return !h->pprev;
}

#endif /* _LINUX_LIST_BL_H */
