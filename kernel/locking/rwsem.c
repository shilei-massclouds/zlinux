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
 * The least significant 2 bits of the owner value has the following
 * meanings when set.
 *  - Bit 0: RWSEM_READER_OWNED - The rwsem is owned by readers
 *  - Bit 1: RWSEM_NONSPINNABLE - Cannot spin on a reader-owned lock
 *
 * When the rwsem is reader-owned and a spinning writer has timed out,
 * the nonspinnable bit will be set to disable optimistic spinning.

 * When a writer acquires a rwsem, it puts its task_struct pointer
 * into the owner field. It is cleared after an unlock.
 *
 * When a reader acquires a rwsem, it will also puts its task_struct
 * pointer into the owner field with the RWSEM_READER_OWNED bit set.
 * On unlock, the owner field will largely be left untouched. So
 * for a free or reader-owned rwsem, the owner value may contain
 * information about the last reader that acquires the rwsem.
 *
 * That information may be helpful in debugging cases where the system
 * seems to hang on a reader owned rwsem especially if only one reader
 * is involved. Ideally we would like to track all the readers that own
 * a rwsem, but the overhead is simply too big.
 *
 * A fast path reader optimistic lock stealing is supported when the rwsem
 * is previously owned by a writer and the following conditions are met:
 *  - rwsem is not currently writer owned
 *  - the handoff isn't set.
 */
#define RWSEM_READER_OWNED  (1UL << 0)
#define RWSEM_NONSPINNABLE  (1UL << 1)
#define RWSEM_OWNER_FLAGS_MASK  (RWSEM_READER_OWNED | RWSEM_NONSPINNABLE)

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

#define RWSEM_READER_SHIFT  8
#define RWSEM_READER_BIAS   (1UL << RWSEM_READER_SHIFT)
#define RWSEM_READER_MASK   (~(RWSEM_READER_BIAS - 1))
#define RWSEM_WRITER_MASK   RWSEM_WRITER_LOCKED
#define RWSEM_LOCK_MASK     (RWSEM_WRITER_MASK|RWSEM_READER_MASK)
#define RWSEM_READ_FAILED_MASK  (RWSEM_WRITER_MASK|RWSEM_FLAG_WAITERS|\
                                 RWSEM_FLAG_HANDOFF|RWSEM_FLAG_READFAIL)

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

/*
 * Wait for the read lock to be granted
 */
static struct rw_semaphore __sched *
rwsem_down_read_slowpath(struct rw_semaphore *sem,
                         long count, unsigned int state)
{
    panic("%s: END\n", __func__);
}

/*
 * The task_struct pointer of the last owning reader will be left in
 * the owner field.
 *
 * Note that the owner value just indicates the task has owned the rwsem
 * previously, it may not be the real owner or one of the real owners
 * anymore when that field is examined, so take it with a grain of salt.
 *
 * The reader non-spinnable bit is preserved.
 */
static inline void __rwsem_set_reader_owned(struct rw_semaphore *sem,
                                            struct task_struct *owner)
{
    unsigned long val = (unsigned long)owner | RWSEM_READER_OWNED |
        (atomic_long_read(&sem->owner) & RWSEM_NONSPINNABLE);

    atomic_long_set(&sem->owner, val);
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
    __rwsem_set_reader_owned(sem, current);
}

/*
 * Set the RWSEM_NONSPINNABLE bits if the RWSEM_READER_OWNED flag
 * remains set. Otherwise, the operation will be aborted.
 */
static inline void rwsem_set_nonspinnable(struct rw_semaphore *sem)
{
    unsigned long owner = atomic_long_read(&sem->owner);

    do {
        if (!(owner & RWSEM_READER_OWNED))
            break;
        if (owner & RWSEM_NONSPINNABLE)
            break;
    } while (!atomic_long_try_cmpxchg(&sem->owner, &owner,
                                      owner | RWSEM_NONSPINNABLE));
}

static inline bool rwsem_read_trylock(struct rw_semaphore *sem, long *cntp)
{
    *cntp = atomic_long_add_return_acquire(RWSEM_READER_BIAS, &sem->count);

    if (WARN_ON_ONCE(*cntp < 0))
        rwsem_set_nonspinnable(sem);

    if (!(*cntp & RWSEM_READ_FAILED_MASK)) {
        rwsem_set_reader_owned(sem);
        return true;
    }

    return false;
}

static inline int __down_read_common(struct rw_semaphore *sem, int state)
{
    long count;

    if (!rwsem_read_trylock(sem, &count)) {
        if (IS_ERR(rwsem_down_read_slowpath(sem, count, state)))
            return -EINTR;
    }
    return 0;
}

static inline void __down_read(struct rw_semaphore *sem)
{
    __down_read_common(sem, TASK_UNINTERRUPTIBLE);
}

void __sched down_read(struct rw_semaphore *sem)
{
    might_sleep();

    __down_read(sem);
}
EXPORT_SYMBOL(down_read);

/*
 * Test the flags in the owner field.
 */
static inline bool rwsem_test_oflags(struct rw_semaphore *sem, long flags)
{
    return atomic_long_read(&sem->owner) & flags;
}

/*
 * Clear the owner's RWSEM_NONSPINNABLE bit if it is set. This should
 * only be called when the reader count reaches 0.
 */
static inline void clear_nonspinnable(struct rw_semaphore *sem)
{
    if (rwsem_test_oflags(sem, RWSEM_NONSPINNABLE))
        atomic_long_andnot(RWSEM_NONSPINNABLE, &sem->owner);
}

/*
 * unlock after reading
 */
static inline void __up_read(struct rw_semaphore *sem)
{
    long tmp;

    tmp = atomic_long_add_return_release(-RWSEM_READER_BIAS, &sem->count);
    if (unlikely((tmp & (RWSEM_LOCK_MASK|RWSEM_FLAG_WAITERS)) ==
                 RWSEM_FLAG_WAITERS)) {
        clear_nonspinnable(sem);
        rwsem_wake(sem);
    }
}

/*
 * release a read lock
 */
void up_read(struct rw_semaphore *sem)
{
    __up_read(sem);
}
EXPORT_SYMBOL(up_read);
