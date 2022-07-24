/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RCULIST_H
#define _LINUX_RCULIST_H

#ifdef __KERNEL__

/*
 * RCU-protected list version
 */
#include <linux/list.h>
#include <linux/rcupdate.h>

/*
 * return the ->next pointer of a list_head in an rcu safe
 * way, we must not access it directly
 */
#define list_next_rcu(list) (*((struct list_head __rcu **)(&(list)->next)))

/*
 * return the first or the next element in an RCU protected hlist
 */
#define hlist_first_rcu(head) (*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_next_rcu(node)  (*((struct hlist_node __rcu **)(&(node)->next)))
#define hlist_pprev_rcu(node) (*((struct hlist_node __rcu **)((node)->pprev)))

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add_rcu(struct list_head *new,
        struct list_head *prev, struct list_head *next)
{
    if (!__list_add_valid(new, prev, next))
        return;

    new->next = next;
    new->prev = prev;
    rcu_assign_pointer(list_next_rcu(prev), new);
    next->prev = new;
}

/**
 * list_add_tail_rcu - add a new entry to rcu-protected list
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as list_add_tail_rcu()
 * or list_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * list_for_each_entry_rcu().
 */
static inline void list_add_tail_rcu(struct list_head *new,
                                     struct list_head *head)
{
    __list_add_rcu(new, head->prev, head);
}

/**
 * hlist_add_head_rcu
 * @n: the element to add to the hash list.
 * @h: the list to add to.
 *
 * Description:
 * Adds the specified element to the specified hlist,
 * while permitting racing traversals.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry_rcu(), used to prevent memory-consistency
 * problems on Alpha CPUs.  Regardless of the type of CPU, the
 * list-traversal primitive must be guarded by rcu_read_lock().
 */
static inline void hlist_add_head_rcu(struct hlist_node *n,
                                      struct hlist_head *h)
{
    struct hlist_node *first = h->first;

    n->next = first;
    WRITE_ONCE(n->pprev, &h->first);
    rcu_assign_pointer(hlist_first_rcu(h), n);
    if (first)
        WRITE_ONCE(first->pprev, &n->next);
}

/**
 * hlist_del_init_rcu - deletes entry from hash list with re-initialization
 * @n: the element to delete from the hash list.
 *
 * Note: list_unhashed() on the node return true after this. It is
 * useful for RCU based read lockfree traversal if the writer side
 * must know if the list entry is still hashed or already unhashed.
 *
 * In particular, it means that we can not poison the forward pointers
 * that may still be used for walking the hash list and we can only
 * zero the pprev pointer so list_unhashed() will return true after
 * this.
 *
 * The caller must take whatever precautions are necessary (such as
 * holding appropriate locks) to avoid racing with another
 * list-mutation primitive, such as hlist_add_head_rcu() or
 * hlist_del_rcu(), running on this same list.  However, it is
 * perfectly legal to run concurrently with the _rcu list-traversal
 * primitives, such as hlist_for_each_entry_rcu().
 */
static inline void hlist_del_init_rcu(struct hlist_node *n)
{
    if (!hlist_unhashed(n)) {
        __hlist_del(n);
        WRITE_ONCE(n->pprev, NULL);
    }
}

#endif  /* __KERNEL__ */

#endif /* _LINUX_RCULIST_H */
