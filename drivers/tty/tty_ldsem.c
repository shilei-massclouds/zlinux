// SPDX-License-Identifier: GPL-2.0
/*
 * Ldisc rw semaphore
 *
 * The ldisc semaphore is semantically a rw_semaphore but which enforces
 * an alternate policy, namely:
 *   1) Supports lock wait timeouts
 *   2) Write waiter has priority
 *   3) Downgrading is not supported
 *
 * Implementation notes:
 *   1) Upper half of semaphore count is a wait count (differs from rwsem
 *  in that rwsem normalizes the upper half to the wait bias)
 *   2) Lacks overflow checking
 *
 * The generic counting was copied and modified from include/asm-generic/rwsem.h
 * by Paul Mackerras <paulus@samba.org>.
 *
 * The scheduling policy was copied and modified from lib/rwsem.c
 * Written by David Howells (dhowells@redhat.com).
 *
 * This implementation incorporates the write lock stealing work of
 * Michel Lespinasse <walken@google.com>.
 *
 * Copyright (C) 2013 Peter Hurley <peter@hurleysoftware.com>
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/tty.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>

#define LDSEM_ACTIVE_MASK  0xffffffffL

#define LDSEM_UNLOCKED      0L
#define LDSEM_ACTIVE_BIAS   1L
#define LDSEM_WAIT_BIAS     (-LDSEM_ACTIVE_MASK-1)
#define LDSEM_READ_BIAS     LDSEM_ACTIVE_BIAS
#define LDSEM_WRITE_BIAS    (LDSEM_WAIT_BIAS + LDSEM_ACTIVE_BIAS)

struct ldsem_waiter {
    struct list_head list;
    struct task_struct *task;
};

/*
 * Initialize an ldsem:
 */
void __init_ldsem(struct ld_semaphore *sem, const char *name,
          struct lock_class_key *key)
{
    atomic_long_set(&sem->count, LDSEM_UNLOCKED);
    sem->wait_readers = 0;
    raw_spin_lock_init(&sem->wait_lock);
    INIT_LIST_HEAD(&sem->read_wait);
    INIT_LIST_HEAD(&sem->write_wait);
}

/*
 * wait for the write lock to be granted
 */
static struct ld_semaphore __sched *
down_write_failed(struct ld_semaphore *sem, long count, long timeout)
{
    panic("%s: END!\n", __func__);
}

static int __ldsem_down_write_nested(struct ld_semaphore *sem,
                                     int subclass, long timeout)
{
    long count;

    count = atomic_long_add_return(LDSEM_WRITE_BIAS, &sem->count);
    if ((count & LDSEM_ACTIVE_MASK) != LDSEM_ACTIVE_BIAS) {
        if (!down_write_failed(sem, count, timeout))
            return 0;
    }
    return 1;
}

/*
 * lock for writing -- returns 1 if successful, 0 if timed out
 */
int __sched ldsem_down_write(struct ld_semaphore *sem, long timeout)
{
    might_sleep();
    return __ldsem_down_write_nested(sem, 0, timeout);
}

static void __ldsem_wake_writer(struct ld_semaphore *sem)
{
    struct ldsem_waiter *waiter;

    waiter = list_entry(sem->write_wait.next, struct ldsem_waiter,
                        list);
    wake_up_process(waiter->task);
}

static void __ldsem_wake_readers(struct ld_semaphore *sem)
{
    panic("%s: END!\n", __func__);
}

/*
 * handle the lock release when processes blocked on it that can now run
 * - if we come here from up_xxxx(), then:
 *   - the 'active part' of count (&0x0000ffff) reached 0 (but may have changed)
 *   - the 'waiting part' of count (&0xffff0000) is -ve (and will still be so)
 * - the spinlock must be held by the caller
 * - woken process blocks are discarded from the list after having task zeroed
 */
static void __ldsem_wake(struct ld_semaphore *sem)
{
    if (!list_empty(&sem->write_wait))
        __ldsem_wake_writer(sem);
    else if (!list_empty(&sem->read_wait))
        __ldsem_wake_readers(sem);
}

static void ldsem_wake(struct ld_semaphore *sem)
{
    unsigned long flags;

    raw_spin_lock_irqsave(&sem->wait_lock, flags);
    __ldsem_wake(sem);
    raw_spin_unlock_irqrestore(&sem->wait_lock, flags);
}

/*
 * release a write lock
 */
void ldsem_up_write(struct ld_semaphore *sem)
{
    long count;

    count = atomic_long_add_return(-LDSEM_WRITE_BIAS, &sem->count);
    if (count < 0)
        ldsem_wake(sem);
}

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int ldsem_down_read_trylock(struct ld_semaphore *sem)
{
    long count = atomic_long_read(&sem->count);

    while (count >= 0) {
        if (atomic_long_try_cmpxchg(&sem->count, &count, count + LDSEM_READ_BIAS))
            return 1;
    }
    return 0;
}

/*
 * release a read lock
 */
void ldsem_up_read(struct ld_semaphore *sem)
{
    long count;

    count = atomic_long_add_return(-LDSEM_READ_BIAS, &sem->count);
    if (count < 0 && (count & LDSEM_ACTIVE_MASK) == 0)
        ldsem_wake(sem);
}
