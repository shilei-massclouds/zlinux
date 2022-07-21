/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LIST_BL_H
#define _LINUX_LIST_BL_H

#include <linux/list.h>
#include <linux/bit_spinlock.h>

#define LIST_BL_LOCKMASK    1UL

#define LIST_BL_BUG_ON(x)

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

static inline bool hlist_bl_unhashed(const struct hlist_bl_node *h)
{
    return !h->pprev;
}

static inline void hlist_bl_lock(struct hlist_bl_head *b)
{
    bit_spin_lock(0, (unsigned long *)b);
}

static inline void hlist_bl_unlock(struct hlist_bl_head *b)
{
    __bit_spin_unlock(0, (unsigned long *)b);
}

static inline bool hlist_bl_is_locked(struct hlist_bl_head *b)
{
    return bit_spin_is_locked(0, (unsigned long *)b);
}

static inline void __hlist_bl_del(struct hlist_bl_node *n)
{
    struct hlist_bl_node *next = n->next;
    struct hlist_bl_node **pprev = n->pprev;

    LIST_BL_BUG_ON((unsigned long)n & LIST_BL_LOCKMASK);

    /* pprev may be `first`, so be careful not to lose the lock bit */
    WRITE_ONCE(*pprev,
               (struct hlist_bl_node *)
               ((unsigned long)next |
                ((unsigned long)*pprev & LIST_BL_LOCKMASK)));
    if (next)
        next->pprev = pprev;
}

#endif /* _LINUX_LIST_BL_H */
