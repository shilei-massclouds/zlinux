/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SPINLOCK_H
#define __LINUX_SPINLOCK_H

#include <linux/typecheck.h>
#include <linux/preempt.h>
#include <linux/linkage.h>
#include <linux/compiler.h>
#include <linux/irqflags.h>
#include <linux/thread_info.h>
#include <linux/kernel.h>
#include <linux/stringify.h>
#include <linux/bottom_half.h>
#include <linux/lockdep.h>
#include <asm/barrier.h>
#include <asm/mmiowb.h>

#define __lockfunc __attribute__((section(".spinlock.text")))

#include <linux/spinlock_types.h>
#include <asm/spinlock.h>

/* Include rwlock functions for !RT */
#include <linux/rwlock.h>

#define raw_spin_lock_init(lock) \
    do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); } while (0)

#define raw_spin_lock_irqsave(lock, flags)      \
    do {                                        \
        typecheck(unsigned long, flags);        \
        flags = _raw_spin_lock_irqsave(lock);   \
    } while (0)

#define raw_spin_unlock_irqrestore(lock, flags)     \
    do {                            \
        typecheck(unsigned long, flags);        \
        _raw_spin_unlock_irqrestore(lock, flags);   \
    } while (0)

#ifndef arch_spin_lock_flags
#define arch_spin_lock_flags(lock, flags)   arch_spin_lock(lock)
#endif

#define raw_spin_lock_irq(lock)     _raw_spin_lock_irq(lock)
#define raw_spin_unlock_irq(lock)   _raw_spin_unlock_irq(lock)
#define raw_spin_lock_bh(lock)      _raw_spin_lock_bh(lock)
#define raw_spin_unlock_bh(lock)    _raw_spin_unlock_bh(lock)

/*
 * Define the various spin_lock methods.  Note we define these
 * regardless of whether CONFIG_SMP or CONFIG_PREEMPTION are set. The
 * various methods are defined as nops in the case they are not
 * required.
 */
#define raw_spin_trylock(lock) __cond_lock(lock, _raw_spin_trylock(lock))

#define raw_spin_lock(lock)     _raw_spin_lock(lock)
#define raw_spin_unlock(lock)   _raw_spin_unlock(lock)

static inline void
do_raw_spin_lock_flags(raw_spinlock_t *lock, unsigned long *flags)
    __acquires(lock)
{
    __acquire(lock);
    arch_spin_lock_flags(&lock->raw_lock, *flags);
    mmiowb_spin_lock();
}

static inline void
do_raw_spin_lock(raw_spinlock_t *lock) __acquires(lock)
{
    __acquire(lock);
    arch_spin_lock(&lock->raw_lock);
    mmiowb_spin_lock();
}

static inline void
do_raw_spin_unlock(raw_spinlock_t *lock) __releases(lock)
{
    mmiowb_spin_unlock();
    arch_spin_unlock(&lock->raw_lock);
    __release(lock);
}

#include <linux/spinlock_api_smp.h>

static __always_inline raw_spinlock_t *spinlock_check(spinlock_t *lock)
{
    return &lock->rlock;
}

#define spin_lock_init(_lock)               \
do {                                        \
    spinlock_check(_lock);                  \
    *(_lock) = __SPIN_LOCK_UNLOCKED(_lock); \
} while (0)

static __always_inline void spin_lock(spinlock_t *lock)
{
    raw_spin_lock(&lock->rlock);
}

static __always_inline void spin_unlock(spinlock_t *lock)
{
    raw_spin_unlock(&lock->rlock);
}

#define spin_lock_irqsave(lock, flags)                  \
do {                                                    \
    raw_spin_lock_irqsave(spinlock_check(lock), flags); \
} while (0)

static __always_inline void
spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
    raw_spin_unlock_irqrestore(&lock->rlock, flags);
}

#define raw_spin_is_locked(lock)    arch_spin_is_locked(&(lock)->raw_lock)

#define assert_spin_locked(lock)    assert_raw_spin_locked(&(lock)->rlock)

static __always_inline void spin_lock_irq(spinlock_t *lock)
{
    raw_spin_lock_irq(&lock->rlock);
}

static __always_inline void spin_unlock_irq(spinlock_t *lock)
{
    raw_spin_unlock_irq(&lock->rlock);
}

static __always_inline void spin_lock_bh(spinlock_t *lock)
{
    raw_spin_lock_bh(&lock->rlock);
}

static __always_inline void spin_unlock_bh(spinlock_t *lock)
{
    raw_spin_unlock_bh(&lock->rlock);
}

/*
 * Always evaluate the 'subclass' argument to avoid that the compiler
 * warns about set-but-not-used variables when building with
 * CONFIG_DEBUG_LOCK_ALLOC=n and with W=1.
 */
#define raw_spin_lock_nested(lock, subclass) \
    _raw_spin_lock(((void)(subclass), (lock)))
#define raw_spin_lock_nest_lock(lock, nest_lock) _raw_spin_lock(lock)

#include <linux/spinlock_api_smp.h>

#endif /* __LINUX_SPINLOCK_H */
