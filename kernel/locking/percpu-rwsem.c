// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/wait.h>
#include <linux/lockdep.h>
#include <linux/percpu-rwsem.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/debug.h>
#include <linux/errno.h>

void __sched percpu_down_write(struct percpu_rw_semaphore *sem)
{
#if 0
    might_sleep();
    rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);

    /* Notify readers to take the slow path. */
    rcu_sync_enter(&sem->rss);

    /*
     * Try set sem->block; this provides writer-writer exclusion.
     * Having sem->block set makes new readers block.
     */
    if (!__percpu_down_write_trylock(sem))
        percpu_rwsem_wait(sem, /* .reader = */ false);

    /* smp_mb() implied by __percpu_down_write_trylock() on success -- D matches A */

    /*
     * If they don't see our store of sem->block, then we are guaranteed to
     * see their sem->read_count increment, and therefore will wait for
     * them.
     */

    /* Wait for all active readers to complete. */
    rcuwait_wait_event(&sem->writer, readers_active_check(sem),
                       TASK_UNINTERRUPTIBLE);
#endif
}
EXPORT_SYMBOL_GPL(percpu_down_write);

void percpu_up_write(struct percpu_rw_semaphore *sem)
{
#if 0
    /*
     * Signal the writer is done, no fast path yet.
     *
     * One reason that we cannot just immediately flip to readers_fast is
     * that new readers might fail to see the results of this writer's
     * critical section.
     *
     * Therefore we force it through the slow path which guarantees an
     * acquire and thereby guarantees the critical section's consistency.
     */
    atomic_set_release(&sem->block, 0);

    /*
     * Prod any pending reader/writer to make progress.
     */
    __wake_up(&sem->waiters, TASK_NORMAL, 1, sem);

    /*
     * Once this completes (at least one RCU-sched grace period hence) the
     * reader fast path will be available again. Safe to use outside the
     * exclusive write lock because its counting.
     */
    rcu_sync_exit(&sem->rss);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(percpu_up_write);

static bool __percpu_down_read_trylock(struct percpu_rw_semaphore *sem)
{
    this_cpu_inc(*sem->read_count);

    /*
     * Due to having preemption disabled the decrement happens on
     * the same CPU as the increment, avoiding the
     * increment-on-one-CPU-and-decrement-on-another problem.
     *
     * If the reader misses the writer's assignment of sem->block, then the
     * writer is guaranteed to see the reader's increment.
     *
     * Conversely, any readers that increment their sem->read_count after
     * the writer looks are guaranteed to see the sem->block value, which
     * in turn means that they are guaranteed to immediately decrement
     * their sem->read_count, so that it doesn't matter that the writer
     * missed them.
     */

    smp_mb(); /* A matches D */

    /*
     * If !sem->block the critical section starts here, matched by the
     * release in percpu_up_write().
     */
    if (likely(!atomic_read_acquire(&sem->block)))
        return true;

    this_cpu_dec(*sem->read_count);

    /* Prod writer to re-evaluate readers_active_check() */
    rcuwait_wake_up(&sem->writer);

    return false;
}

static void percpu_rwsem_wait(struct percpu_rw_semaphore *sem, bool reader)
{
    panic("%s: END!\n", __func__);
}

bool __sched __percpu_down_read(struct percpu_rw_semaphore *sem, bool try)
{
    if (__percpu_down_read_trylock(sem))
        return true;

    if (try)
        return false;

    preempt_enable();
    percpu_rwsem_wait(sem, /* .reader = */ true);
    preempt_disable();

    return true;
}
EXPORT_SYMBOL_GPL(__percpu_down_read);
