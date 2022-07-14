// SPDX-License-Identifier: GPL-2.0
/* kernel/rwsem.c: R/W semaphores, public implementation
 *
 * Written by David Howells (dhowells@redhat.com).
 * Derived from asm-i386/semaphore.h
 *
 * Writer lock-stealing by Alex Shi <alex.shi@intel.com>
 * and Michel Lespinasse <walken@google.com>
 *
 * Optimistic spinning by Tim Chen <tim.c.chen@intel.com>
 * and Davidlohr Bueso <davidlohr@hp.com>. Based on mutexes.
 *
 * Rwsem count bit fields re-definition and rwsem rearchitecture by
 * Waiman Long <longman@redhat.com> and
 * Peter Zijlstra <peterz@infradead.org>.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#include <linux/sched/debug.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/signal.h>
//#include <linux/sched/clock.h>
#include <linux/export.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>

/*
 * On 64-bit architectures, the bit definitions of the count are:
 *
 * Bit  0    - writer locked bit
 * Bit  1    - waiters present bit
 * Bit  2    - lock handoff bit
 * Bits 3-7  - reserved
 * Bits 8-62 - 55-bit reader count
 * Bit  63   - read fail bit
 *
 * On 32-bit architectures, the bit definitions of the count are:
 *
 * Bit  0    - writer locked bit
 * Bit  1    - waiters present bit
 * Bit  2    - lock handoff bit
 * Bits 3-7  - reserved
 * Bits 8-30 - 23-bit reader count
 * Bit  31   - read fail bit
 *
 * It is not likely that the most significant bit (read fail bit) will ever
 * be set. This guard bit is still checked anyway in the down_read() fastpath
 * just in case we need to use up more of the reader bits for other purpose
 * in the future.
 *
 * atomic_long_fetch_add() is used to obtain reader lock, whereas
 * atomic_long_cmpxchg() will be used to obtain writer lock.
 *
 * There are three places where the lock handoff bit may be set or cleared.
 * 1) rwsem_mark_wake() for readers     -- set, clear
 * 2) rwsem_try_write_lock() for writers    -- set, clear
 * 3) rwsem_del_waiter()            -- clear
 *
 * For all the above cases, wait_lock will be held. A writer must also
 * be the first one in the wait_list to be eligible for setting the handoff
 * bit. So concurrent setting/clearing of handoff bit is not possible.
 */
#define RWSEM_WRITER_LOCKED (1UL << 0)
#define RWSEM_FLAG_WAITERS  (1UL << 1)
#define RWSEM_FLAG_HANDOFF  (1UL << 2)
#define RWSEM_FLAG_READFAIL (1UL << (BITS_PER_LONG - 1))


/*
 * All writes to owner are protected by WRITE_ONCE() to make sure that
 * store tearing can't happen as optimistic spinners may read and use
 * the owner value concurrently without lock. Read from owner, however,
 * may not need READ_ONCE() as long as the pointer value is only used
 * for comparison and isn't being dereferenced.
 */
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
    atomic_long_set(&sem->owner, (long)current);
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
    atomic_long_set(&sem->owner, 0);
}

/*
 * Initialize an rwsem:
 */
void __init_rwsem(struct rw_semaphore *sem, const char *name,
          struct lock_class_key *key)
{
    atomic_long_set(&sem->count, RWSEM_UNLOCKED_VALUE);
    raw_spin_lock_init(&sem->wait_lock);
    INIT_LIST_HEAD(&sem->wait_list);
    atomic_long_set(&sem->owner, 0L);
#if 0
    osq_lock_init(&sem->osq);
#endif
}
EXPORT_SYMBOL(__init_rwsem);

/*
 * handle waking up a waiter on the semaphore
 * - up_read/up_write has decremented the active part of count if we come here
 */
static struct rw_semaphore *rwsem_wake(struct rw_semaphore *sem)
{
#if 0
    unsigned long flags;
    DEFINE_WAKE_Q(wake_q);

    raw_spin_lock_irqsave(&sem->wait_lock, flags);

    if (!list_empty(&sem->wait_list))
        rwsem_mark_wake(sem, RWSEM_WAKE_ANY, &wake_q);

    raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
    wake_up_q(&wake_q);

    return sem;
#endif
    panic("%s: NO IMPLEMENTATION!\n", __func__);
}

static inline bool rwsem_write_trylock(struct rw_semaphore *sem)
{
    long tmp = RWSEM_UNLOCKED_VALUE;

    if (atomic_long_try_cmpxchg_acquire(&sem->count, &tmp,
                                        RWSEM_WRITER_LOCKED)) {
        rwsem_set_owner(sem);
        return true;
    }

    return false;
}

/*
 * Wait until we successfully acquire the write lock
 */
static struct rw_semaphore __sched *
rwsem_down_write_slowpath(struct rw_semaphore *sem, int state)
{
    panic("%s: NO IMPLEMENTATION!\n", __func__);
}

/*
 * lock for writing
 */
static inline int __down_write_common(struct rw_semaphore *sem, int state)
{
    if (unlikely(!rwsem_write_trylock(sem))) {
        if (IS_ERR(rwsem_down_write_slowpath(sem, state)))
            return -EINTR;
    }

    return 0;
}

static inline void __down_write(struct rw_semaphore *sem)
{
    __down_write_common(sem, TASK_UNINTERRUPTIBLE);
}

/*
 * lock for writing
 */
void __sched down_write(struct rw_semaphore *sem)
{
    might_sleep();
    __down_write(sem);
}
EXPORT_SYMBOL(down_write);

/*
 * unlock after writing
 */
static inline void __up_write(struct rw_semaphore *sem)
{
    long tmp;

    rwsem_clear_owner(sem);
    tmp = atomic_long_fetch_add_release(-RWSEM_WRITER_LOCKED, &sem->count);
    if (unlikely(tmp & RWSEM_FLAG_WAITERS))
        rwsem_wake(sem);
}

/*
 * release a write lock
 */
void up_write(struct rw_semaphore *sem)
{
    __up_write(sem);
}
EXPORT_SYMBOL(up_write);
