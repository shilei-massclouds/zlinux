/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Statically sized hash table implementation
 * (C) 2012  Sasha Levin <levinsasha928@gmail.com>
 */

#ifndef _LINUX_HASHTABLE_H
#define _LINUX_HASHTABLE_H

#include <linux/list.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/hash.h>
#include <linux/rculist.h>

#define DEFINE_HASHTABLE(name, bits)                        \
    struct hlist_head name[1 << (bits)] =                   \
            { [0 ... ((1 << (bits)) - 1)] = HLIST_HEAD_INIT }

#define DECLARE_HASHTABLE(name, bits) \
    struct hlist_head name[1 << (bits)]

#define HASH_SIZE(name) (ARRAY_SIZE(name))
#define HASH_BITS(name) ilog2(HASH_SIZE(name))

/**
 * hash_for_each - iterate over a hashtable
 * @name: hashtable to iterate
 * @bkt: integer to use as bucket loop cursor
 * @obj: the type * to use as a loop cursor for each entry
 * @member: the name of the hlist_node within the struct
 */
#define hash_for_each(name, bkt, obj, member)               \
    for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
            (bkt)++)\
        hlist_for_each_entry(obj, &name[bkt], member)

#endif /* _LINUX_HASHTABLE_H */
