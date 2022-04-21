#ifndef __LINUX_SPINLOCK_API_SMP_H
#define __LINUX_SPINLOCK_API_SMP_H

#ifndef __LINUX_SPINLOCK_H
# error "please don't include this file directly"
#endif

/*
 * include/linux/spinlock_api_smp.h
 *
 * spinlock API declarations on SMP (and debug)
 * (implemented in kernel/spinlock.c)
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

unsigned long __lockfunc
_raw_spin_lock_irqsave(raw_spinlock_t *lock) __acquires(lock);

void __lockfunc
_raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
    __releases(lock);

void __lockfunc _raw_spin_lock_irq(raw_spinlock_t *lock)
    __acquires(lock);

void __lockfunc
_raw_spin_unlock_irq(raw_spinlock_t *lock)  __releases(lock);

int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock);
void __lockfunc _raw_spin_lock(raw_spinlock_t *lock) __acquires(lock);
void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock) __releases(lock);

static inline unsigned long
__raw_spin_lock_irqsave(raw_spinlock_t *lock)
{
    unsigned long flags;

    local_irq_save(flags);
    preempt_disable();
    /*
     * On lockdep we dont want the hand-coded irq-enable of
     * do_raw_spin_lock_flags() code, because lockdep assumes
     * that interrupts are not re-enabled during lock-acquire:
     */
    do_raw_spin_lock_flags(lock, &flags);
    return flags;
}

static inline void
__raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
{
    do_raw_spin_unlock(lock);
    local_irq_restore(flags);
    preempt_enable();
}

static inline void __raw_spin_lock_irq(raw_spinlock_t *lock)
{
    local_irq_disable();
    preempt_disable();
    do_raw_spin_lock(lock);
}

static inline void __raw_spin_unlock_irq(raw_spinlock_t *lock)
{
    do_raw_spin_unlock(lock);
    local_irq_enable();
    preempt_enable();
}

static inline void __raw_spin_unlock(raw_spinlock_t *lock)
{
    do_raw_spin_unlock(lock);
    preempt_enable();
}

static inline void __raw_spin_lock(raw_spinlock_t *lock)
{
    preempt_disable();
    do_raw_spin_lock(lock);
}

#endif /* __LINUX_SPINLOCK_API_SMP_H */
