#ifndef __LINUX_SPINLOCK_TYPES_H
#define __LINUX_SPINLOCK_TYPES_H

/*
 * include/linux/spinlock_types.h - generic spinlock type definitions
 *                                  and initializers
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

#include <asm/spinlock_types.h>
//#include <linux/lockdep_types.h>

typedef struct raw_spinlock {
    arch_spinlock_t raw_lock;
} raw_spinlock_t;

#define __RAW_SPIN_LOCK_INITIALIZER(lockname) \
    { .raw_lock = __ARCH_SPIN_LOCK_UNLOCKED, }

#define __RAW_SPIN_LOCK_UNLOCKED(lockname) \
    (raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)

#define DEFINE_RAW_SPINLOCK(x) \
    raw_spinlock_t x = __RAW_SPIN_LOCK_UNLOCKED(x)

#define DEFINE_SPINLOCK(x)  spinlock_t x = __SPIN_LOCK_UNLOCKED(x)

//#include <linux/rwlock_types.h>

#endif /* __LINUX_SPINLOCK_TYPES_H */
