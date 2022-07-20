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
