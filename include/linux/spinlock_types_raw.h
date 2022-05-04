#ifndef __LINUX_SPINLOCK_TYPES_RAW_H
#define __LINUX_SPINLOCK_TYPES_RAW_H

#include <linux/types.h>
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

#endif /* __LINUX_SPINLOCK_TYPES_RAW_H */
