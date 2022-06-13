// SPDX-License-Identifier: GPL-2.0-only
/*
 *  kernel/sched/core.c
 *
 *  Core kernel scheduler code and related syscalls
 *
 *  Copyright (C) 1991-2002  Linus Torvalds
 */

#include "sched.h"

#if 0
#include <linux/nospec.h>

#include <linux/kcov.h>
#include <linux/scs.h>

#include <asm/switch_to.h>
#include <asm/tlb.h>

#include "../workqueue_internal.h"
#include "../../fs/io-wq.h"
#include "../smpboot.h"

#include "pelt.h"
#include "smp.h"
#endif

DEFINE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

/**
 * wake_up_process - Wake up a specific process
 * @p: The process to be woken up.
 *
 * Attempt to wake up the nominated process and move it to the set of runnable
 * processes.
 *
 * Return: 1 if the process was woken up, 0 if it was already running.
 *
 * This function executes a full memory barrier before accessing the task state.
 */
int wake_up_process(struct task_struct *p)
{
    panic("%s: NOT-implemented!\n", __func__);
    return 0;
    //return try_to_wake_up(p, TASK_NORMAL, 0);
}
EXPORT_SYMBOL(wake_up_process);

asmlinkage __visible void __sched schedule(void)
{
    panic("%s: NO implementation!\n", __func__);
#if 0
    struct task_struct *tsk = current;

    sched_submit_work(tsk);
    do {
        preempt_disable();
        __schedule(SM_NONE);
        sched_preempt_enable_no_resched();
    } while (need_resched());
    sched_update_worker(tsk);
#endif
}
EXPORT_SYMBOL(schedule);

/**
 * schedule_preempt_disabled - called with preemption disabled
 *
 * Returns with preemption disabled. Note: preempt_count must be 1
 */
void __sched schedule_preempt_disabled(void)
{
    sched_preempt_enable_no_resched();
    schedule();
    preempt_disable();
}

static bool __wake_q_add(struct wake_q_head *head, struct task_struct *task)
{
    struct wake_q_node *node = &task->wake_q;

    /*
     * Atomically grab the task, if ->wake_q is !nil already it means
     * it's already queued (either by us or someone else) and will get the
     * wakeup due to that.
     *
     * In order to ensure that a pending wakeup will observe our pending
     * state, even in the failed case, an explicit smp_mb() must be used.
     */
    smp_mb__before_atomic();
    if (unlikely(cmpxchg_relaxed(&node->next, NULL, WAKE_Q_TAIL)))
        return false;

    /*
     * The head is context local, there can be no concurrency.
     */
    *head->lastp = node;
    head->lastp = &node->next;
    return true;
}

/**
 * wake_q_add() - queue a wakeup for 'later' waking.
 * @head: the wake_q_head to add @task to
 * @task: the task to queue for 'later' wakeup
 *
 * Queue a task for later wakeup, most likely by the wake_up_q() call in the
 * same context, _HOWEVER_ this is not guaranteed, the wakeup can come
 * instantly.
 *
 * This function must be used as-if it were wake_up_process(); IOW the task
 * must be ready to be woken at this location.
 */
void wake_q_add(struct wake_q_head *head, struct task_struct *task)
{
    if (__wake_q_add(head, task))
        get_task_struct(task);
}

void wake_up_q(struct wake_q_head *head)
{
    struct wake_q_node *node = head->first;

    while (node != WAKE_Q_TAIL) {
        struct task_struct *task;

        task = container_of(node, struct task_struct, wake_q);
        /* Task can safely be re-inserted now: */
        node = node->next;
        task->wake_q.next = NULL;

        /*
         * wake_up_process() executes a full barrier, which pairs with
         * the queueing in wake_q_add() so as not to miss wakeups.
         */
        wake_up_process(task);
        put_task_struct(task);
    }
}

unsigned long long nr_context_switches(void)
{
    int i;
    unsigned long long sum = 0;

    for_each_possible_cpu(i)
        sum += cpu_rq(i)->nr_switches;

    return sum;
}
