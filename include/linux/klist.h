/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  klist.h - Some generic list helpers, extending struct list_head a bit.
 *
 *  Implementations are found in lib/klist.c
 *
 *  Copyright (C) 2005 Patrick Mochel
 */

#ifndef _LINUX_KLIST_H
#define _LINUX_KLIST_H

#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/list.h>

struct klist_node {
    void                *n_klist;   /* never access directly */
    struct list_head    n_node;
    struct kref         n_ref;
};

struct klist {
    spinlock_t          k_lock;
    struct list_head    k_list;
    void                (*get)(struct klist_node *);
    void                (*put)(struct klist_node *);
} __attribute__ ((aligned (sizeof(void *))));

extern void klist_init(struct klist *k,
                       void (*get)(struct klist_node *),
                       void (*put)(struct klist_node *));

extern void klist_add_tail(struct klist_node *n, struct klist *k);
extern void klist_add_head(struct klist_node *n, struct klist *k);

#endif /* _LINUX_KLIST_H */
