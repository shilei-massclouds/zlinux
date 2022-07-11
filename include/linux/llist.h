/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LLIST_H
#define LLIST_H
/*
 * Lock-less NULL terminated single linked list
 *
 * Cases where locking is not needed:
 * If there are multiple producers and multiple consumers, llist_add can be
 * used in producers and llist_del_all can be used in consumers simultaneously
 * without locking. Also a single consumer can use llist_del_first while
 * multiple producers simultaneously use llist_add, without any locking.
 *
 * Cases where locking is needed:
 * If we have multiple consumers with llist_del_first used in one consumer, and
 * llist_del_first or llist_del_all used in other consumers, then a lock is
 * needed.  This is because llist_del_first depends on list->first->next not
 * changing, but without lock protection, there's no way to be sure about that
 * if a preemption happens in the middle of the delete operation and on being
 * preempted back, the list->first is the same as before causing the cmpxchg in
 * llist_del_first to succeed. For example, while a llist_del_first operation
 * is in progress in one consumer, then a llist_del_first, llist_add,
 * llist_add (or llist_del_all, llist_add, llist_add) sequence in another
 * consumer may cause violations.
 *
 * This can be summarized as follows:
 *
 *           |   add    | del_first |  del_all
 * add       |    -     |     -     |     -
 * del_first |          |     L     |     L
 * del_all   |          |           |     -
 *
 * Where, a particular row's operation can happen concurrently with a column's
 * operation, with "-" being no lock needed, while "L" being lock is needed.
 *
 * The list entries deleted via llist_del_all can be traversed with
 * traversing function such as llist_for_each etc.  But the list
 * entries can not be traversed safely before deleted from the list.
 * The order of deleted entries is from the newest to the oldest added
 * one.  If you want to traverse from the oldest to the newest, you
 * must reverse the order by yourself before traversing.
 *
 * The basic atomic operation of this list is cmpxchg on long.  On
 * architectures that don't have NMI-safe cmpxchg implementation, the
 * list can NOT be used in NMI handlers.  So code that uses the list in
 * an NMI handler should depend on CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG.
 *
 * Copyright 2010,2011 Intel Corp.
 *   Author: Huang Ying <ying.huang@intel.com>
 */

#include <linux/atomic.h>
#if 0
#include <linux/container_of.h>
#endif
#include <linux/stddef.h>
#include <linux/types.h>

struct llist_head {
    struct llist_node *first;
};

struct llist_node {
    struct llist_node *next;
};

#endif /* LLIST_H */
