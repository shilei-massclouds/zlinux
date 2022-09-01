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

static void init_one_lru(struct list_lru_one *l)
{
    INIT_LIST_HEAD(&l->list);
    l->nr_items = 0;
}

int __list_lru_init(struct list_lru *lru, bool memcg_aware,
                    struct lock_class_key *key, struct shrinker *shrinker)
{
    int i;

    lru->node = kcalloc(nr_node_ids, sizeof(*lru->node), GFP_KERNEL);
    if (!lru->node)
        return -ENOMEM;

    for_each_node(i) {
        spin_lock_init(&lru->node[i].lock);
        init_one_lru(&lru->node[i].lru);
    }

    return 0;
}
EXPORT_SYMBOL_GPL(__list_lru_init);

static inline struct list_lru_one *
list_lru_from_memcg_idx(struct list_lru *lru, int nid, int idx)
{
    return &lru->node[nid].lru;
}

unsigned long list_lru_count_one(struct list_lru *lru,
                                 int nid, struct mem_cgroup *memcg)
{
    struct list_lru_one *l;
    long count;

    rcu_read_lock();
    l = list_lru_from_memcg_idx(lru, nid, -1);
    count = l ? READ_ONCE(l->nr_items) : 0;
    rcu_read_unlock();

    if (unlikely(count < 0))
        count = 0;

    return count;
}
EXPORT_SYMBOL_GPL(list_lru_count_one);
