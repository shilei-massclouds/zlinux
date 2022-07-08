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

#endif /* _LRU_LIST_H */
