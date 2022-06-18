/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_XARRAY_H
#define _LINUX_XARRAY_H
/*
 * eXtensible Arrays
 * Copyright (c) 2017 Microsoft Corporation
 * Author: Matthew Wilcox <willy@infradead.org>
 *
 * See Documentation/core-api/xarray.rst for how to use the XArray.
 */

#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/**
 * struct xarray - The anchor of the XArray.
 * @xa_lock: Lock that protects the contents of the XArray.
 *
 * To use the xarray, define it statically or embed it in your data structure.
 * It is a very small data structure, so it does not usually make sense to
 * allocate it separately and keep a pointer to it in your data structure.
 *
 * You may use the xa_lock to protect your own data structures as well.
 */
/*
 * If all of the entries in the array are NULL, @xa_head is a NULL pointer.
 * If the only non-NULL entry in the array is at index 0, @xa_head is that
 * entry.  If any other entry in the array is non-NULL, @xa_head points
 * to an @xa_node.
 */
struct xarray {
    spinlock_t  xa_lock;
/* private: The rest of the data structure is not to be used directly. */
    gfp_t       xa_flags;
    void __rcu *xa_head;
};

#define XARRAY_INIT(name, flags) {                      \
    .xa_lock    = __SPIN_LOCK_UNLOCKED(name.xa_lock),   \
    .xa_flags   = flags,                                \
    .xa_head    = NULL,                                 \
}

/**
 * xa_init_flags() - Initialise an empty XArray with flags.
 * @xa: XArray.
 * @flags: XA_FLAG values.
 *
 * If you need to initialise an XArray with special flags (eg you need
 * to take the lock from interrupt context), use this function instead
 * of xa_init().
 *
 * Context: Any context.
 */
static inline void xa_init_flags(struct xarray *xa, gfp_t flags)
{
    spin_lock_init(&xa->xa_lock);
    xa->xa_flags = flags;
    xa->xa_head = NULL;
}

#endif /* _LINUX_XARRAY_H */
