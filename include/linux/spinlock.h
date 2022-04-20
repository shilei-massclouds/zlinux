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
//#include <linux/bottom_half.h>
#include <asm/barrier.h>
#include <asm/mmiowb.h>

#define __lockfunc __attribute__((section(".spinlock.text")))

#include <linux/spinlock_types.h>
#include <asm/spinlock.h>

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

static inline void
do_raw_spin_lock_flags(raw_spinlock_t *lock, unsigned long *flags)
    __acquires(lock)
{
    __acquire(lock);
    arch_spin_lock_flags(&lock->raw_lock, *flags);
    mmiowb_spin_lock();
}

static inline void do_raw_spin_lock(raw_spinlock_t *lock) __acquires(lock)
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

#endif /* __LINUX_SPINLOCK_H */
