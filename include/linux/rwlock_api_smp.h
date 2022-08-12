#ifndef __LINUX_RWLOCK_API_SMP_H
#define __LINUX_RWLOCK_API_SMP_H

#ifndef __LINUX_SPINLOCK_API_SMP_H
# error "please don't include this file directly"
#endif

/*
 * include/linux/rwlock_api_smp.h
 *
 * spinlock API declarations on SMP (and debug)
 * (implemented in kernel/spinlock.c)
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

void __lockfunc _raw_read_lock(rwlock_t *lock)  __acquires(lock);
void __lockfunc _raw_write_lock(rwlock_t *lock) __acquires(lock);

int __lockfunc _raw_read_trylock(rwlock_t *lock);
int __lockfunc _raw_write_trylock(rwlock_t *lock);

void __lockfunc _raw_read_unlock(rwlock_t *lock)    __releases(lock);
void __lockfunc _raw_write_unlock(rwlock_t *lock)   __releases(lock);

static inline void __raw_write_lock(rwlock_t *lock)
{
    preempt_disable();
    do_raw_write_lock(lock);
}

static inline void __raw_write_unlock(rwlock_t *lock)
{
    do_raw_write_unlock(lock);
    preempt_enable();
}

static inline void __raw_read_lock(rwlock_t *lock)
{
    preempt_disable();
    do_raw_read_lock(lock);
}

static inline void __raw_read_unlock(rwlock_t *lock)
{
    do_raw_read_unlock(lock);
    preempt_enable();
}

void __lockfunc _raw_write_lock_irq(rwlock_t *lock) __acquires(lock);
void __lockfunc _raw_write_unlock_irq(rwlock_t *lock) __releases(lock);

static inline void __raw_write_lock_irq(rwlock_t *lock)
{
    local_irq_disable();
    preempt_disable();
    do_raw_write_lock(lock);
}

static inline void __raw_write_unlock_irq(rwlock_t *lock)
{
    do_raw_write_unlock(lock);
    local_irq_enable();
    preempt_enable();
}

#endif /* __LINUX_RWLOCK_API_SMP_H */
