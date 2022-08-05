// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2013 Red Hat, Inc. and Parallels Inc. All rights reserved.
 * Authors: David Chinner and Glauber Costa
 *
 * Generic LRU infrastructure
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/list_lru.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/memcontrol.h>
#include "slab.h"
#include "internal.h"

void list_lru_destroy(struct list_lru *lru)
{
    /* Already destroyed or not yet initialized? */
    if (!lru->node)
        return;

    kfree(lru->node);
    lru->node = NULL;
}
EXPORT_SYMBOL_GPL(list_lru_destroy);

static inline struct list_lru_one *
list_lru_from_kmem(struct list_lru *lru, int nid, void *ptr,
                   struct mem_cgroup **memcg_ptr)
{
    if (memcg_ptr)
        *memcg_ptr = NULL;
    return &lru->node[nid].lru;
}

bool list_lru_add(struct list_lru *lru, struct list_head *item)
{
    int nid = page_to_nid(virt_to_page(item));
    struct list_lru_node *nlru = &lru->node[nid];
    struct mem_cgroup *memcg;
    struct list_lru_one *l;

    spin_lock(&nlru->lock);
    if (list_empty(item)) {
        l = list_lru_from_kmem(lru, nid, item, &memcg);
        list_add_tail(item, &l->list);
        nlru->nr_items++;
        spin_unlock(&nlru->lock);
        return true;
    }
    spin_unlock(&nlru->lock);
    return false;
}
EXPORT_SYMBOL_GPL(list_lru_add);

bool list_lru_del(struct list_lru *lru, struct list_head *item)
{
    int nid = page_to_nid(virt_to_page(item));
    struct list_lru_node *nlru = &lru->node[nid];
    struct list_lru_one *l;

    spin_lock(&nlru->lock);
    if (!list_empty(item)) {
        l = list_lru_from_kmem(lru, nid, item, NULL);
        list_del_init(item);
        l->nr_items--;
        nlru->nr_items--;
        spin_unlock(&nlru->lock);
        return true;
    }
    spin_unlock(&nlru->lock);
    return false;
}
EXPORT_SYMBOL_GPL(list_lru_del);
