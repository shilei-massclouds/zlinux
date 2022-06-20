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
#include <linux/slab.h>

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

int
dup_user_cpus_ptr(struct task_struct *dst, struct task_struct *src, int node)
{
    if (!src->user_cpus_ptr)
        return 0;

    dst->user_cpus_ptr = kmalloc_node(cpumask_size(), GFP_KERNEL, node);
    if (!dst->user_cpus_ptr)
        return -ENOMEM;

    cpumask_copy(dst->user_cpus_ptr, src->user_cpus_ptr);
    return 0;
}

/*
 * Perform scheduler related setup for a newly forked process p.
 * p is forked by current.
 *
 * __sched_fork() is basic setup used by init_idle() too:
 */
static void __sched_fork(unsigned long clone_flags, struct task_struct *p)
{
    pr_warn("%s: NEED to be implemented!\n", __func__);
}

/*
 * fork()/clone()-time setup:
 */
int sched_fork(unsigned long clone_flags, struct task_struct *p)
{
    __sched_fork(clone_flags, p);
    /*
     * We mark the process as NEW here. This guarantees that
     * nobody will actually run it, and a signal or other external
     * event cannot wake it up and insert it on the runqueue either.
     */
    p->__state = TASK_NEW;

    pr_warn("%s: NEED to be implemented!\n", __func__);

    return 0;
}

/**
 * finish_task_switch - clean up after a task-switch
 * @prev: the thread we just switched away from.
 *
 * finish_task_switch must be called after the context switch, paired
 * with a prepare_task_switch call before the context switch.
 * finish_task_switch will reconcile locking set up by prepare_task_switch,
 * and do any other architecture-specific cleanup actions.
 *
 * Note that we may have delayed dropping an mm in context_switch(). If
 * so, we finish that here outside of the runqueue lock. (Doing it
 * with the lock held can cause deadlocks; see schedule() for
 * details.)
 *
 * The context switch have flipped the stack from under us and restored the
 * local variables which were saved when this task called schedule() in the
 * past. prev == current is still correct but we need to recalculate this_rq
 * because prev may have moved to another CPU.
 */
static struct rq *
finish_task_switch(struct task_struct *prev) __releases(rq->lock)
{
    unsigned int prev_state;
    struct rq *rq = this_rq();
    struct mm_struct *mm = rq->prev_mm;

    /*
     * The previous task will have left us with a preempt_count of 2
     * because it left us after:
     *
     *  schedule()
     *    preempt_disable();            // 1
     *    __schedule()
     *      raw_spin_lock_irq(&rq->lock)    // 2
     *
     * Also, see FORK_PREEMPT_COUNT.
     */
    if (WARN_ONCE(preempt_count() != 2*PREEMPT_DISABLE_OFFSET,
                  "corrupted preempt_count: %s/%d/0x%x\n",
                  current->comm, current->pid, preempt_count()))
        preempt_count_set(FORK_PREEMPT_COUNT);

    rq->prev_mm = NULL;

    /*
     * A task struct has one reference for the use as "current".
     * If a task dies, then it sets TASK_DEAD in tsk->state and calls
     * schedule one last time. The schedule call will never return, and
     * the scheduled task must drop that reference.
     *
     * We must observe prev->state before clearing prev->on_cpu (in
     * finish_task), otherwise a concurrent wakeup can get prev
     * running on another CPU and we could rave with its RUNNING -> DEAD
     * transition, resulting in a double drop.
     */
#if 0
    prev_state = READ_ONCE(prev->__state);
    vtime_task_switch(prev);
    perf_event_task_sched_in(prev, current);
    finish_task(prev);
    tick_nohz_task_switch();
    finish_lock_switch(rq);
    finish_arch_post_lock_switch();
    kcov_finish_switch(current);

    /*
     * kmap_local_sched_out() is invoked with rq::lock held and
     * interrupts disabled. There is no requirement for that, but the
     * sched out code does not have an interrupt enabled section.
     * Restoring the maps on sched in does not require interrupts being
     * disabled either.
     */
    kmap_local_sched_in();

    fire_sched_in_preempt_notifiers(current);
    /*
     * When switching through a kernel thread, the loop in
     * membarrier_{private,global}_expedited() may have observed that
     * kernel thread and not issued an IPI. It is therefore possible to
     * schedule between user->kernel->user threads without passing though
     * switch_mm(). Membarrier requires a barrier after storing to
     * rq->curr, before returning to userspace, so provide them here:
     *
     * - a full memory barrier for {PRIVATE,GLOBAL}_EXPEDITED, implicitly
     *   provided by mmdrop(),
     * - a sync_core for SYNC_CORE.
     */
    if (mm) {
        membarrier_mm_sync_core_before_usermode(mm);
        mmdrop_sched(mm);
    }
    if (unlikely(prev_state == TASK_DEAD)) {
        if (prev->sched_class->task_dead)
            prev->sched_class->task_dead(prev);

        /* Task is done with its stack. */
        put_task_stack(prev);

        put_task_struct_rcu_user(prev);
    }
#endif

    return rq;
}

/**
 * schedule_tail - first thing a freshly forked thread must call.
 * @prev: the thread we just switched away from.
 */
asmlinkage __visible void
schedule_tail(struct task_struct *prev) __releases(rq->lock)
{
    /*
     * New tasks start with FORK_PREEMPT_COUNT, see there and
     * finish_task_switch() for details.
     *
     * finish_task_switch() will drop rq->lock() and lower preempt_count
     * and the preempt_enable() will end up enabling preemption (on
     * PREEMPT_COUNT kernels).
     */

    finish_task_switch(prev);
    preempt_enable();

#if 0
    if (current->set_child_tid)
        put_user(task_pid_vnr(current), current->set_child_tid);

    calculate_sigpending();
#endif
}

/*
 * wake_up_new_task - wake up a newly created task for the first time.
 *
 * This function will do some initial scheduler statistics housekeeping
 * that must be done for every newly created context, then puts the task
 * on the runqueue and wakes it.
 */
void wake_up_new_task(struct task_struct *p)
{
    struct rq_flags rf;
    struct rq *rq;

    raw_spin_lock_irqsave(&p->pi_lock, rf.flags);
    WRITE_ONCE(p->__state, TASK_RUNNING);

    /*
     * Fork balancing, do it here and not earlier because:
     *  - cpus_ptr can change in the fork path
     *  - any previously selected CPU might disappear through hotplug
     *
     * Use __set_task_cpu() to avoid calling sched_class::migrate_task_rq,
     * as we're not fully set-up yet.
     */
    p->recent_used_cpu = task_cpu(p);
#if 0
    rseq_migrate(p);
    __set_task_cpu(p, select_task_rq(p, task_cpu(p), WF_FORK));
#endif

    panic("%s: END!\n", __func__);
}
