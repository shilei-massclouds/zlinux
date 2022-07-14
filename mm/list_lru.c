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
