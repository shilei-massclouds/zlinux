/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2013 Red Hat, Inc. and Parallels Inc. All rights reserved.
 * Authors: David Chinner and Glauber Costa
 *
 * Generic LRU infrastructure
 */
#ifndef _LRU_LIST_H
#define _LRU_LIST_H

#include <linux/list.h>
#include <linux/nodemask.h>
#if 0
#include <linux/shrinker.h>
#endif
#include <linux/xarray.h>

struct list_lru_one {
    struct list_head    list;
    /* may become negative during memcg reparenting */
    long                nr_items;
};

struct list_lru_node {
    /* protects all lists on the node, including per cgroup */
    spinlock_t      lock;
    /* global list, used for the root cgroup in cgroup aware lrus */
    struct list_lru_one lru;
    long            nr_items;
} ____cacheline_aligned_in_smp;

struct list_lru {
    struct list_lru_node *node;
};

void list_lru_destroy(struct list_lru *lru);

/**
 * list_lru_add: add an element to the lru list's tail
 * @list_lru: the lru pointer
 * @item: the item to be added.
 *
 * If the element is already part of a list, this function returns doing
 * nothing. Therefore the caller does not need to keep state about whether or
 * not the element already belongs in the list and is allowed to lazy update
 * it. Note however that this is valid for *a* list, not *this* list. If
 * the caller organize itself in a way that elements can be in more than
 * one type of list, it is up to the caller to fully remove the item from
 * the previous list (with list_lru_del() for instance) before moving it
 * to @list_lru
 *
 * Return value: true if the list was updated, false otherwise
 */
bool list_lru_add(struct list_lru *lru, struct list_head *item);

#endif /* _LRU_LIST_H */
