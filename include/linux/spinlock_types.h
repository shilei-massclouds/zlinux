#ifndef __LINUX_SPINLOCK_TYPES_H
#define __LINUX_SPINLOCK_TYPES_H

/*
 * include/linux/spinlock_types.h - generic spinlock type definitions
 *                                  and initializers
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

#include <linux/spinlock_types_raw.h>

/* Non PREEMPT_RT kernels map spinlock to raw_spinlock */
typedef struct spinlock {
    union {
        struct raw_spinlock rlock;
    };
} spinlock_t;

#define ___SPIN_LOCK_INITIALIZER(lockname)  \
    { .raw_lock = __ARCH_SPIN_LOCK_UNLOCKED }

#define __SPIN_LOCK_INITIALIZER(lockname) \
    { { .rlock = ___SPIN_LOCK_INITIALIZER(lockname) } }

#define __SPIN_LOCK_UNLOCKED(lockname) \
    (spinlock_t) __SPIN_LOCK_INITIALIZER(lockname)

#include <linux/rwlock_types.h>

#endif /* __LINUX_SPINLOCK_TYPES_H */
