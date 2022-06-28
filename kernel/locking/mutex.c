// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/locking/mutex.c
 *
 * Mutexes: blocking mutual exclusion locks
 *
 * Started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * Many thanks to Arjan van de Ven, Thomas Gleixner, Steven Rostedt and
 * David Howells for suggestions and improvements.
 *
 *  - Adaptive spinning for mutexes by Peter Zijlstra. (Ported to mainline
 *    from the -rt tree, where it was originally implemented for rtmutexes
 *    by Steven Rostedt, based on work by Gregory Haskins, Peter Morreale
 *    and Sven Dietrich.
 *
 * Also see Documentation/locking/mutex-design.rst.
 */
#include <linux/mutex.h>
#include <linux/ww_mutex.h>
#include <linux/sched/signal.h>
/*
#include <linux/sched/rt.h>
*/
#include <linux/sched/wake_q.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/lockdep_types.h>
/*
#include <linux/interrupt.h>
#include <linux/debug_locks.h>
#include <linux/osq_lock.h>
*/

#include "mutex.h"
#include "ww_mutex.h"

#define MUTEX_WARN_ON(cond)

void
__mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
{
    atomic_long_set(&lock->owner, 0);
    raw_spin_lock_init(&lock->wait_lock);
    INIT_LIST_HEAD(&lock->wait_list);
}
EXPORT_SYMBOL(__mutex_init);

/*
 * Optimistic trylock that only works in the uncontended case. Make sure to
 * follow with a __mutex_trylock() before failing.
 */
static __always_inline bool __mutex_trylock_fast(struct mutex *lock)
{
    unsigned long zero = 0UL;
    unsigned long curr = (unsigned long)current;

    if (atomic_long_try_cmpxchg_acquire(&lock->owner, &zero, curr))
        return true;

    return false;
}

static __always_inline bool __mutex_unlock_fast(struct mutex *lock)
{
    unsigned long curr = (unsigned long)current;

    return atomic_long_try_cmpxchg_release(&lock->owner, &curr, 0UL);
}

/*
 * @owner: contains: 'struct task_struct *' to the current lock owner,
 * NULL means not owned. Since task_struct pointers are aligned at
 * at least L1_CACHE_BYTES, we have low bits to store extra state.
 *
 * Bit0 indicates a non-empty waiter list; unlock must issue a wakeup.
 * Bit1 indicates unlock needs to hand the lock to the top-waiter
 * Bit2 indicates handoff has been done and we're waiting for pickup.
 */
#define MUTEX_FLAG_WAITERS  0x01
#define MUTEX_FLAG_HANDOFF  0x02
#define MUTEX_FLAG_PICKUP   0x04

#define MUTEX_FLAGS         0x07

static inline unsigned long __owner_flags(unsigned long owner)
{
    return owner & MUTEX_FLAGS;
}

static inline struct task_struct *__owner_task(unsigned long owner)
{
    return (struct task_struct *)(owner & ~MUTEX_FLAGS);
}

/*
 * Returns: __mutex_owner(lock) on failure or NULL on success.
 */
static inline struct task_struct *
__mutex_trylock_common(struct mutex *lock, bool handoff)
{
    unsigned long owner, curr = (unsigned long)current;

    owner = atomic_long_read(&lock->owner);
    for (;;) { /* must loop, can race against a flag */
        unsigned long flags = __owner_flags(owner);
        unsigned long task = owner & ~MUTEX_FLAGS;

        if (task) {
            if (flags & MUTEX_FLAG_PICKUP) {
                if (task != curr)
                    break;
                flags &= ~MUTEX_FLAG_PICKUP;
            } else if (handoff) {
                if (flags & MUTEX_FLAG_HANDOFF)
                    break;
                flags |= MUTEX_FLAG_HANDOFF;
            } else {
                break;
            }
        } else {
            MUTEX_WARN_ON(flags & (MUTEX_FLAG_HANDOFF | MUTEX_FLAG_PICKUP));
            task = curr;
        }

        if (atomic_long_try_cmpxchg_acquire(&lock->owner,
                                            &owner, task | flags)) {
            if (task == curr)
                return NULL;
            break;
        }
    }

    return __owner_task(owner);
}

/*
 * Actual trylock that will work on any unlocked state.
 */
static inline bool __mutex_trylock(struct mutex *lock)
{
    return !__mutex_trylock_common(lock, false);
}

static inline void __mutex_set_flag(struct mutex *lock, unsigned long flag)
{
    atomic_long_or(flag, &lock->owner);
}

static inline void __mutex_clear_flag(struct mutex *lock, unsigned long flag)
{
    atomic_long_andnot(flag, &lock->owner);
}

static inline bool
__mutex_waiter_is_first(struct mutex *lock, struct mutex_waiter *waiter)
{
    return list_first_entry(&lock->wait_list, struct mutex_waiter, list) == waiter;
}

/*
 * Add @waiter to a given location in the lock wait_list and set the
 * FLAG_WAITERS flag if it's the first waiter.
 */
static void
__mutex_add_waiter(struct mutex *lock, struct mutex_waiter *waiter,
           struct list_head *list)
{
    list_add_tail(&waiter->list, list);
    if (__mutex_waiter_is_first(lock, waiter))
        __mutex_set_flag(lock, MUTEX_FLAG_WAITERS);
}

/*
 * Trylock or set HANDOFF
 */
static inline bool __mutex_trylock_or_handoff(struct mutex *lock, bool handoff)
{
    return !__mutex_trylock_common(lock, handoff);
}

static void
__mutex_remove_waiter(struct mutex *lock, struct mutex_waiter *waiter)
{
    list_del(&waiter->list);
    if (likely(list_empty(&lock->wait_list)))
        __mutex_clear_flag(lock, MUTEX_FLAGS);
}

/*
 * Lock a mutex (possibly interruptible), slowpath:
 */
static __always_inline int __sched
__mutex_lock_common(struct mutex *lock, unsigned int state,
                    unsigned int subclass, struct lockdep_map *nest_lock,
                    unsigned long ip,
                    struct ww_acquire_ctx *ww_ctx, const bool use_ww_ctx)
{
    int ret;
    struct ww_mutex *ww;
    struct mutex_waiter waiter;

    if (!use_ww_ctx)
        ww_ctx = NULL;

    might_sleep();

    ww = container_of(lock, struct ww_mutex, base);
    if (ww_ctx) {
        if (unlikely(ww_ctx == READ_ONCE(ww->ctx)))
            return -EALREADY;

        /*
         * Reset the wounded flag after a kill. No other process can
         * race and wound us here since they can't have a valid owner
         * pointer if we don't have any locks held.
         */
        if (ww_ctx->acquired == 0)
            ww_ctx->wounded = 0;
    }

    preempt_disable();

    if (__mutex_trylock(lock)) {
        /* got the lock, yay! */
        if (ww_ctx)
            ww_mutex_set_context_fastpath(ww, ww_ctx);
        preempt_enable();
        return 0;
    }

    raw_spin_lock(&lock->wait_lock);
    /*
     * After waiting to acquire the wait_lock, try again.
     */
    if (__mutex_trylock(lock)) {
        if (ww_ctx)
            __ww_mutex_check_waiters(lock, ww_ctx);

        goto skip_wait;
    }

    waiter.task = current;
    if (use_ww_ctx)
        waiter.ww_ctx = ww_ctx;

    if (!use_ww_ctx) {
        /* add waiting tasks to the end of the waitqueue (FIFO): */
        __mutex_add_waiter(lock, &waiter, &lock->wait_list);
    } else {
        /*
         * Add in stamp order, waking up waiters that must kill
         * themselves.
         */
        ret = __ww_mutex_add_waiter(&waiter, lock, ww_ctx);
        if (ret)
            goto err_early_kill;
    }

    set_current_state(state);
    for (;;) {
        bool first;

        /*
         * Once we hold wait_lock, we're serialized against
         * mutex_unlock() handing the lock off to us, do a trylock
         * before testing the error conditions to make sure we pick up
         * the handoff.
         */
        if (__mutex_trylock(lock))
            goto acquired;

        /*
         * Check for signals and kill conditions while holding
         * wait_lock. This ensures the lock cancellation is ordered
         * against mutex_unlock() and wake-ups do not go missing.
         */
#if 0
        if (signal_pending_state(state, current)) {
            ret = -EINTR;
            goto err;
        }
#endif

        if (ww_ctx) {
            ret = __ww_mutex_check_kill(lock, &waiter, ww_ctx);
            if (ret)
                goto err;
        }

        raw_spin_unlock(&lock->wait_lock);
        schedule_preempt_disabled();

        first = __mutex_waiter_is_first(lock, &waiter);

        set_current_state(state);
        /*
         * Here we order against unlock; we must either see it change
         * state back to RUNNING and fall through the next schedule(),
         * or we must see its unlock and acquire.
         */
        if (__mutex_trylock_or_handoff(lock, first))
            break;

        raw_spin_lock(&lock->wait_lock);
    }

    raw_spin_lock(&lock->wait_lock);
acquired:
    __set_current_state(TASK_RUNNING);

    if (ww_ctx) {
        /*
         * Wound-Wait; we stole the lock (!first_waiter), check the
         * waiters as anyone might want to wound us.
         */
        if (!ww_ctx->is_wait_die &&
            !__mutex_waiter_is_first(lock, &waiter))
            __ww_mutex_check_waiters(lock, ww_ctx);
    }

    __mutex_remove_waiter(lock, &waiter);

 skip_wait:
    /* got the lock - cleanup and rejoice! */

    if (ww_ctx)
        ww_mutex_lock_acquired(ww, ww_ctx);

    raw_spin_unlock(&lock->wait_lock);
    preempt_enable();
    return 0;

 err:
    __set_current_state(TASK_RUNNING);
    __mutex_remove_waiter(lock, &waiter);

 err_early_kill:
    raw_spin_unlock(&lock->wait_lock);
    preempt_enable();
    return ret;
}

static int __sched
__mutex_lock(struct mutex *lock, unsigned int state, unsigned int subclass,
             struct lockdep_map *nest_lock, unsigned long ip)
{
    return __mutex_lock_common(lock, state, subclass, nest_lock, ip, NULL, false);
}

static noinline void __sched
__mutex_lock_slowpath(struct mutex *lock)
{
    __mutex_lock(lock, TASK_UNINTERRUPTIBLE, 0, NULL, _RET_IP_);
}

/**
 * mutex_lock - acquire the mutex
 * @lock: the mutex to be acquired
 *
 * Lock the mutex exclusively for this task. If the mutex is not
 * available right now, it will sleep until it can get it.
 *
 * The mutex must later on be released by the same task that
 * acquired it. Recursive locking is not allowed. The task
 * may not exit without first unlocking the mutex. Also, kernel
 * memory where the mutex resides must not be freed with
 * the mutex still locked. The mutex must first be initialized
 * (or statically defined) before it can be locked. memset()-ing
 * the mutex to 0 is not allowed.
 *
 * (The CONFIG_DEBUG_MUTEXES .config option turns on debugging
 * checks that will enforce the restrictions and will also do
 * deadlock debugging)
 *
 * This function is similar to (but not equivalent to) down().
 */
void __sched mutex_lock(struct mutex *lock)
{
    if (!__mutex_trylock_fast(lock))
        __mutex_lock_slowpath(lock);
}
EXPORT_SYMBOL(mutex_lock);

/*
 * Give up ownership to a specific task, when @task = NULL, this is equivalent
 * to a regular unlock. Sets PICKUP on a handoff, clears HANDOFF, preserves
 * WAITERS. Provides RELEASE semantics like a regular unlock, the
 * __mutex_trylock() provides a matching ACQUIRE semantics for the handoff.
 */
static void __mutex_handoff(struct mutex *lock, struct task_struct *task)
{
    unsigned long owner = atomic_long_read(&lock->owner);

    for (;;) {
        unsigned long new;

        MUTEX_WARN_ON(__owner_task(owner) != current);
        MUTEX_WARN_ON(owner & MUTEX_FLAG_PICKUP);

        new = (owner & MUTEX_FLAG_WAITERS);
        new |= (unsigned long)task;
        if (task)
            new |= MUTEX_FLAG_PICKUP;

        if (atomic_long_try_cmpxchg_release(&lock->owner, &owner, new))
            break;
    }
}

/*
 * Release the lock, slowpath:
 */
static noinline void __sched
__mutex_unlock_slowpath(struct mutex *lock, unsigned long ip)
{
    struct task_struct *next = NULL;
    DEFINE_WAKE_Q(wake_q);
    unsigned long owner;

    /*
     * Release the lock before (potentially) taking the spinlock such that
     * other contenders can get on with things ASAP.
     *
     * Except when HANDOFF, in that case we must not clear the owner field,
     * but instead set it to the top waiter.
     */
    owner = atomic_long_read(&lock->owner);
    for (;;) {
        MUTEX_WARN_ON(__owner_task(owner) != current);
        MUTEX_WARN_ON(owner & MUTEX_FLAG_PICKUP);

        if (owner & MUTEX_FLAG_HANDOFF)
            break;

        if (atomic_long_try_cmpxchg_release(&lock->owner, &owner,
                                            __owner_flags(owner))) {
            if (owner & MUTEX_FLAG_WAITERS)
                break;

            return;
        }
    }

    raw_spin_lock(&lock->wait_lock);
    if (!list_empty(&lock->wait_list)) {
        /* get the first entry from the wait-list: */
        struct mutex_waiter *waiter =
            list_first_entry(&lock->wait_list, struct mutex_waiter, list);

        next = waiter->task;

        wake_q_add(&wake_q, next);
    }

    if (owner & MUTEX_FLAG_HANDOFF)
        __mutex_handoff(lock, next);

    raw_spin_unlock(&lock->wait_lock);

    wake_up_q(&wake_q);
}

/**
 * mutex_unlock - release the mutex
 * @lock: the mutex to be released
 *
 * Unlock a mutex that has been locked by this task previously.
 *
 * This function must not be used in interrupt context. Unlocking
 * of a not locked mutex is not allowed.
 *
 * This function is similar to (but not equivalent to) up().
 */
void __sched mutex_unlock(struct mutex *lock)
{
    if (__mutex_unlock_fast(lock))
        return;
    __mutex_unlock_slowpath(lock, _RET_IP_);
}
EXPORT_SYMBOL(mutex_unlock);

static noinline int __sched
__mutex_lock_killable_slowpath(struct mutex *lock)
{
    return __mutex_lock(lock, TASK_KILLABLE, 0, NULL, _RET_IP_);
}

/**
 * mutex_lock_killable() - Acquire the mutex, interruptible by fatal signals.
 * @lock: The mutex to be acquired.
 *
 * Lock the mutex like mutex_lock().  If a signal which will be fatal to
 * the current process is delivered while the process is sleeping, this
 * function will return without acquiring the mutex.
 *
 * Context: Process context.
 * Return: 0 if the lock was successfully acquired or %-EINTR if a
 * fatal signal arrived.
 */
int __sched mutex_lock_killable(struct mutex *lock)
{
    might_sleep();

    if (__mutex_trylock_fast(lock))
        return 0;

    return __mutex_lock_killable_slowpath(lock);
}
EXPORT_SYMBOL(mutex_lock_killable);
