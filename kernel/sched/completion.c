// SPDX-License-Identifier: GPL-2.0

/*
 * Generic wait-for-completion handler;
 *
 * It differs from semaphores in that their default case is the opposite,
 * wait_for_completion default blocks whereas semaphore default non-block. The
 * interface also makes it easy to 'complete' multiple waiting threads,
 * something which isn't entirely natural for semaphores.
 *
 * But more importantly, the primitive documents the usage. Semaphores would
 * typically be used for exclusion which gives rise to priority inversion.
 * Waiting for completion is a typically sync point, but not an exclusion point.
 */

/**
 * complete: - signals a single thread waiting on this completion
 * @x:  holds the state of this particular completion
 *
 * This will wake up a single thread waiting on this completion. Threads will be
 * awakened in the same order in which they were queued.
 *
 * See also complete_all(), wait_for_completion() and related routines.
 *
 * If this function wakes up a task, it executes a full memory barrier before
 * accessing the task state.
 */
void complete(struct completion *x)
{
    unsigned long flags;

    raw_spin_lock_irqsave(&x->wait.lock, flags);

    if (x->done != UINT_MAX)
        x->done++;
    swake_up_locked(&x->wait);
    raw_spin_unlock_irqrestore(&x->wait.lock, flags);
}
EXPORT_SYMBOL(complete);

static inline long __sched
do_wait_for_common(struct completion *x,
                   long (*action)(long), long timeout, int state)
{
    if (!x->done) {
        DECLARE_SWAITQUEUE(wait);

        do {
#if 0
            if (signal_pending_state(state, current)) {
                timeout = -ERESTARTSYS;
                break;
            }
#endif
            __prepare_to_swait(&x->wait, &wait);
            __set_current_state(state);
            raw_spin_unlock_irq(&x->wait.lock);
            timeout = action(timeout);
            raw_spin_lock_irq(&x->wait.lock);
        } while (!x->done && timeout);

        panic("%s: 1!\n", __func__);
    }

    panic("%s: END!\n", __func__);
}

static inline long __sched
__wait_for_common(struct completion *x,
                  long (*action)(long), long timeout, int state)
{
    might_sleep();

    complete_acquire(x);

    raw_spin_lock_irq(&x->wait.lock);
    timeout = do_wait_for_common(x, action, timeout, state);
    raw_spin_unlock_irq(&x->wait.lock);

    complete_release(x);

    return timeout;
}

static long __sched
wait_for_common(struct completion *x, long timeout, int state)
{
    return __wait_for_common(x, schedule_timeout, timeout, state);
}

/**
 * wait_for_completion_killable: - waits for completion of a task (killable)
 * @x:  holds the state of this particular completion
 *
 * This waits to be signaled for completion of a specific task. It can be
 * interrupted by a kill signal.
 *
 * Return: -ERESTARTSYS if interrupted, 0 if completed.
 */
int __sched wait_for_completion_killable(struct completion *x)
{
    long t = wait_for_common(x, MAX_SCHEDULE_TIMEOUT, TASK_KILLABLE);
    if (t == -ERESTARTSYS)
        return t;
    return 0;
}
EXPORT_SYMBOL(wait_for_completion_killable);
