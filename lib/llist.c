// SPDX-License-Identifier: GPL-2.0-only
/*
 * Lock-less NULL terminated single linked list
 *
 * The basic atomic operation of this list is cmpxchg on long.  On
 * architectures that don't have NMI-safe cmpxchg implementation, the
 * list can NOT be used in NMI handlers.  So code that uses the list in
 * an NMI handler should depend on CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG.
 *
 * Copyright 2010,2011 Intel Corp.
 *   Author: Huang Ying <ying.huang@intel.com>
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/llist.h>

/**
 * llist_add_batch - add several linked entries in batch
 * @new_first:  first entry in batch to be added
 * @new_last:   last entry in batch to be added
 * @head:   the head for your lock-less list
 *
 * Return whether list is empty before adding.
 */
bool llist_add_batch(struct llist_node *new_first, struct llist_node *new_last,
                     struct llist_head *head)
{
    struct llist_node *first;

    do {
        new_last->next = first = READ_ONCE(head->first);
    } while (cmpxchg(&head->first, first, new_first) != first);

    return !first;
}
EXPORT_SYMBOL_GPL(llist_add_batch);

/**
 * llist_reverse_order - reverse order of a llist chain
 * @head:   first item of the list to be reversed
 *
 * Reverse the order of a chain of llist entries and return the
 * new first entry.
 */
struct llist_node *llist_reverse_order(struct llist_node *head)
{
    struct llist_node *new_head = NULL;

    while (head) {
        struct llist_node *tmp = head;
        head = head->next;
        tmp->next = new_head;
        new_head = tmp;
    }

    return new_head;
}
EXPORT_SYMBOL_GPL(llist_reverse_order);
