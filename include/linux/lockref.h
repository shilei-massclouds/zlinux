/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_LOCKREF_H
#define __LINUX_LOCKREF_H

/*
 * Locked reference counts.
 *
 * These are different from just plain atomic refcounts in that they
 * are atomic with respect to the spinlock that goes with them.  In
 * particular, there can be implementations that don't actually get
 * the spinlock for the common decrement/increment operations, but they
 * still have to check that the operation is done semantically as if
 * the spinlock had been taken (using a cmpxchg operation that covers
 * both the lock and the count word, or using memory transactions, for
 * example).
 */

#include <linux/spinlock.h>
#include <generated/bounds.h>

struct lockref {
    struct {
        spinlock_t lock;
        int count;
    };
};

extern void lockref_get(struct lockref *);

#endif /* __LINUX_LOCKREF_H */
