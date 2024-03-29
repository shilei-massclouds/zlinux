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

/**
 * hlist_for_each_entry_rcu - iterate over rcu list of given type
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the hlist_node within the struct.
 * @cond:   optional lockdep expression if called from non-RCU protection.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as hlist_add_head_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
#define hlist_for_each_entry_rcu(pos, head, member, cond...)        \
    for (pos = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),\
                                typeof(*(pos)), member);            \
         pos; \
         pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
            &(pos)->member)), typeof(*(pos)), member))

/*
 * Check during list traversal that we are within an RCU reader
 */

#define check_arg_count_one(dummy)

#define __list_check_rcu(dummy, cond, extra...) \
    ({ check_arg_count_one(extra); })

#define __list_check_srcu(cond) ({ })

/**
 * list_entry_rcu - get the struct for this entry
 * @ptr:        the &struct list_head pointer.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define list_entry_rcu(ptr, type, member) \
    container_of(READ_ONCE(ptr), type, member)

/**
 * list_for_each_entry_rcu  -   iterate over rcu list of given type
 * @pos:    the type * to use as a loop cursor.
 * @head:   the head for your list.
 * @member: the name of the list_head within the struct.
 * @cond:   optional lockdep expression if called from non-RCU protection.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as list_add_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
#define list_for_each_entry_rcu(pos, head, member, cond...)     \
    for (__list_check_rcu(dummy, ## cond, 0),           \
         pos = list_entry_rcu((head)->next, typeof(*pos), member);  \
        &pos->member != (head);                 \
        pos = list_entry_rcu(pos->member.next, typeof(*pos), member))

/**
 * list_del_rcu - deletes entry from list without re-initialization
 * @entry: the element to delete from the list.
 *
 * Note: list_empty() on entry does not return true after this,
 * the entry is in an undefined state. It is useful for RCU based
 * lockfree traversal.
 *
 * In particular, it means that we can not poison the forward
 * pointers that may still be used for walking the list.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as list_del_rcu()
 * or list_add_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * list_for_each_entry_rcu().
 *
 * Note that the caller is not permitted to immediately free
 * the newly deleted entry.  Instead, either synchronize_rcu()
 * or call_rcu() must be used to defer freeing until an RCU
 * grace period has elapsed.
 */
static inline void list_del_rcu(struct list_head *entry)
{
    __list_del_entry(entry);
    entry->prev = LIST_POISON2;
}

/**
 * list_add_rcu - add a new entry to rcu-protected list
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as list_add_rcu()
 * or list_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * list_for_each_entry_rcu().
 */
static inline
void list_add_rcu(struct list_head *new, struct list_head *head)
{
    __list_add_rcu(new, head, head->next);
}

#endif  /* __KERNEL__ */

#endif /* _LINUX_RCULIST_H */
