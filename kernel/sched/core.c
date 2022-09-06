// SPDX-License-Identifier: GPL-2.0-only
/*
 *  kernel/sched/core.c
 *
 *  Core kernel scheduler code and related syscalls
 *
 *  Copyright (C) 1991-2002  Linus Torvalds
 */

#include <linux/highmem.h>
#if 0
#include <linux/hrtimer_api.h>
#include <linux/ktime_api.h>
#include <linux/sched/signal.h>
#include <linux/syscalls_api.h>
#include <linux/debug_locks.h>
#include <linux/prefetch.h>
#include <linux/capability.h>
#include <linux/pgtable_api.h>
#include <linux/wait_bit.h>
#include <linux/cpumask_api.h>
#endif
#include <linux/jiffies.h>
#include <linux/spinlock_api.h>
#if 0
#include <linux/lockdep_api.h>
#include <linux/hardirq.h>
#include <linux/softirq.h>
#include <linux/refcount_api.h>
#endif
#include <linux/topology.h>
#include <linux/sched/clock.h>
#if 0
#include <linux/sched/cond_resched.h>
#include <linux/sched/rseq_api.h>
#endif
#include <linux/sched/nohz.h>
#include <linux/sched/isolation.h>
#include <linux/sched/debug.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/mm.h>
#include <linux/sched/rt.h>

#include <linux/init_task.h>
#include <linux/mmzone.h>
#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/cpuset.h>
#include <linux/interrupt.h>
#if 0
#include <linux/context_tracking.h>
#include <linux/delayacct.h>
#include <linux/ioprio.h>
#include <linux/kallsyms.h>
#include <linux/kcov.h>
#include <linux/kprobes.h>
#include <linux/llist_api.h>
#include <linux/mutex_api.h>
#include <linux/nmi.h>
#include <linux/nospec.h>
#include <linux/perf_event_api.h>
#include <linux/profile.h>
#include <linux/psi.h>
#include <linux/sched/wake_q.h>
#include <linux/scs.h>
#include <linux/syscalls.h>
#include <linux/vtime.h>
#include <linux/workqueue_api.h>
#endif
#include <linux/wait_api.h>
#include <linux/rcuwait_api.h>
#include <linux/slab.h>
#include <linux/mmu_context.h>
#include <linux/kernel_stat.h>

#include <asm/switch_to.h>
#include <uapi/linux/sched/types.h>

#include <asm/tlb.h>

#include "sched.h"
#include "stats.h"
#include "pelt.h"
#if 0
#include "autogroup.h"

#include "smp.h"
#endif

#include "../workqueue_internal.h"
#include "../../fs/io-wq.h"
#include "../smpboot.h"

#define for_each_clamp_id(clamp_id) \
    for ((clamp_id) = 0; (clamp_id) < UCLAMP_CNT; (clamp_id)++)

/*
 * sched_setparam() passes in -1 for its policy, to let the functions
 * it calls know not to change it.
 */
#define SETPARAM_POLICY -1

struct migration_arg {
    struct task_struct      *task;
    int                     dest_cpu;
    struct set_affinity_pending *pending;
};

/*
 * @refs: number of wait_for_completion()
 * @stop_pending: is @stop_work in use
 */
struct set_affinity_pending {
    refcount_t              refs;
    unsigned int            stop_pending;
    struct completion       done;
    struct cpu_stop_work    stop_work;
    struct migration_arg    arg;
};

static struct rq *
finish_task_switch(struct task_struct *prev) __releases(rq->lock);

bool sched_smp_initialized __read_mostly;

/*
 * This static key is used to reduce the uclamp overhead in the fast path. It
 * primarily disables the call to uclamp_rq_{inc, dec}() in
 * enqueue/dequeue_task().
 *
 * This allows users to continue to enable uclamp in their kernel config with
 * minimum uclamp overhead in the fast path.
 *
 * As soon as userspace modifies any of the uclamp knobs, the static key is
 * enabled, since we have an actual users that make use of uclamp
 * functionality.
 *
 * The knobs that would enable this static key are:
 *
 *   * A task modifying its uclamp value with sched_setattr().
 *   * An admin modifying the sysctl_sched_uclamp_{min, max} via procfs.
 *   * An admin modifying the cgroup cpu.uclamp.{min, max}
 */
DEFINE_STATIC_KEY_FALSE(sched_uclamp_used);

DEFINE_PER_CPU(struct kernel_stat, kstat);
DEFINE_PER_CPU(struct kernel_cpustat, kernel_cpustat);

EXPORT_PER_CPU_SYMBOL(kstat);
EXPORT_PER_CPU_SYMBOL(kernel_cpustat);

__read_mostly int scheduler_running;

static DEFINE_STATIC_KEY_FALSE(preempt_notifier_key);

/*
 * Nice levels are multiplicative, with a gentle 10% change for every
 * nice level changed. I.e. when a CPU-bound task goes from nice 0 to
 * nice 1, it will get ~10% less CPU time than another CPU-bound task
 * that remained on nice 0.
 *
 * The "10% effect" is relative and cumulative: from _any_ nice level,
 * if you go up 1 level, it's -10% CPU usage, if you go down 1 level
 * it's +10% CPU usage. (to achieve that we use a multiplier of 1.25.
 * If a task goes up by ~10% and another task goes down by ~10% then
 * the relative distance between them is ~25%.)
 */
const int sched_prio_to_weight[40] = {
 /* -20 */     88761,     71755,     56483,     46273,     36291,
 /* -15 */     29154,     23254,     18705,     14949,     11916,
 /* -10 */      9548,      7620,      6100,      4904,      3906,
 /*  -5 */      3121,      2501,      1991,      1586,      1277,
 /*   0 */      1024,       820,       655,       526,       423,
 /*   5 */       335,       272,       215,       172,       137,
 /*  10 */       110,        87,        70,        56,        45,
 /*  15 */        36,        29,        23,        18,        15,
};

/*
 * Inverse (2^32/x) values of the sched_prio_to_weight[] array, precalculated.
 *
 * In cases where the weight does not change often, we can use the
 * precalculated inverse to speed up arithmetics by turning divisions
 * into multiplications:
 */
const u32 sched_prio_to_wmult[40] = {
 /* -20 */     48388,     59856,     76040,     92818,    118348,
 /* -15 */    147320,    184698,    229616,    287308,    360437,
 /* -10 */    449829,    563644,    704093,    875809,   1099582,
 /*  -5 */   1376151,   1717300,   2157191,   2708050,   3363326,
 /*   0 */   4194304,   5237765,   6557202,   8165337,  10153587,
 /*   5 */  12820798,  15790321,  19976592,  24970740,  31350126,
 /*  10 */  39045157,  49367440,  61356676,  76695844,  95443717,
 /*  15 */ 119304647, 148102320, 186737708, 238609294, 286331153,
};

DEFINE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

static void balance_push(struct rq *rq);

struct callback_head balance_push_callback = {
    .next = NULL,
    .func = (void (*)(struct callback_head *))balance_push,
};

static inline struct cpumask *clear_user_cpus_ptr(struct task_struct *p)
{
    struct cpumask *user_mask = NULL;

    swap(p->user_cpus_ptr, user_mask);

    return user_mask;
}

static inline void prepare_task(struct task_struct *next)
{
    /*
     * Claim the task as running, we do this before switching to it
     * such that any running task will have this set.
     *
     * See the ttwu() WF_ON_CPU case and its ordering comment.
     */
    WRITE_ONCE(next->on_cpu, 1);
}

/*
 * Invoked from try_to_wake_up() to check whether the task can be woken up.
 *
 * The caller holds p::pi_lock if p != current or has preemption
 * disabled when p == current.
 *
 * The rules of PREEMPT_RT saved_state:
 *
 *   The related locking code always holds p::pi_lock when updating
 *   p::saved_state, which means the code is fully serialized in both cases.
 *
 *   The lock wait and lock wakeups happen via TASK_RTLOCK_WAIT. No other
 *   bits set. This allows to distinguish all wakeup scenarios.
 */
static __always_inline
bool ttwu_state_match(struct task_struct *p, unsigned int state, int *success)
{
    if (READ_ONCE(p->__state) & state) {
        *success = 1;
        return true;
    }

    return false;
}

static void
ttwu_stat(struct task_struct *p, int cpu, int wake_flags)
{
}

/*
 * resched_curr - mark rq's current task 'to be rescheduled now'.
 *
 * On UP this means the setting of the need_resched flag, on SMP it
 * might also involve a cross-CPU call to trigger the scheduler on
 * the target CPU.
 */
void resched_curr(struct rq *rq)
{
    struct task_struct *curr = rq->curr;
    int cpu;

    if (test_tsk_need_resched(curr))
        return;

    cpu = cpu_of(rq);

    if (cpu == smp_processor_id()) {
        set_tsk_need_resched(curr);
        set_preempt_need_resched();
        return;
    }

    panic("%s: END!\n", __func__);
}

void check_preempt_curr(struct rq *rq, struct task_struct *p, int flags)
{
    if (p->sched_class == rq->curr->sched_class)
        rq->curr->sched_class->check_preempt_curr(rq, p, flags);
    else if (p->sched_class > rq->curr->sched_class)
        resched_curr(rq);

    /*
     * A queue event has occurred, and we're going to schedule.  In
     * this case, we can save a useless back to back clock update.
     */
    if (task_on_rq_queued(rq->curr) && test_tsk_need_resched(rq->curr))
        rq_clock_skip_update(rq);
}

/*
 * Mark the task runnable and perform wakeup-preemption.
 */
static void ttwu_do_wakeup(struct rq *rq,
                           struct task_struct *p,
                           int wake_flags,
                           struct rq_flags *rf)
{
    check_preempt_curr(rq, p, wake_flags);
    WRITE_ONCE(p->__state, TASK_RUNNING);

    if (p->sched_class->task_woken) {
#if 0
        /*
         * Our task @p is fully woken up and running; so it's safe to
         * drop the rq->lock, hereafter rq is only used for statistics.
         */
        rq_unpin_lock(rq, rf);
        p->sched_class->task_woken(rq, p);
        rq_repin_lock(rq, rf);
#endif
        panic("%s: 1!\n", __func__);
    }

    if (rq->idle_stamp) {
        panic("%s: 2!\n", __func__);
    }
}

/*
 * Consider @p being inside a wait loop:
 *
 *   for (;;) {
 *      set_current_state(TASK_UNINTERRUPTIBLE);
 *
 *      if (CONDITION)
 *         break;
 *
 *      schedule();
 *   }
 *   __set_current_state(TASK_RUNNING);
 *
 * between set_current_state() and schedule(). In this case @p is still
 * runnable, so all that needs doing is change p->state back to TASK_RUNNING in
 * an atomic manner.
 *
 * By taking task_rq(p)->lock we serialize against schedule(), if @p->on_rq
 * then schedule() must still happen and p->state can be changed to
 * TASK_RUNNING. Otherwise we lost the race, schedule() has happened, and we
 * need to do a full wakeup with enqueue.
 *
 * Returns: %true when the wakeup is done,
 *          %false otherwise.
 */
static int ttwu_runnable(struct task_struct *p, int wake_flags)
{
    struct rq_flags rf;
    struct rq *rq;
    int ret = 0;

    rq = __task_rq_lock(p, &rf);
    if (task_on_rq_queued(p)) {
        /* check_preempt_curr() may use rq clock */
        update_rq_clock(rq);
        ttwu_do_wakeup(rq, p, wake_flags, &rf);
        ret = 1;
    }
    __task_rq_unlock(rq, &rf);

    return ret;
}

/**
 * try_to_wake_up - wake up a thread
 * @p: the thread to be awakened
 * @state: the mask of task states that can be woken
 * @wake_flags: wake modifier flags (WF_*)
 *
 * Conceptually does:
 *
 *   If (@state & @p->state) @p->state = TASK_RUNNING.
 *
 * If the task was not queued/runnable, also place it back on a runqueue.
 *
 * This function is atomic against schedule() which would dequeue the task.
 *
 * It issues a full memory barrier before accessing @p->state, see the comment
 * with set_current_state().
 *
 * Uses p->pi_lock to serialize against concurrent wake-ups.
 *
 * Relies on p->pi_lock stabilizing:
 *  - p->sched_class
 *  - p->cpus_ptr
 *  - p->sched_task_group
 * in order to do migration, see its use of select_task_rq()/set_task_cpu().
 *
 * Tries really hard to only take one task_rq(p)->lock for performance.
 * Takes rq->lock in:
 *  - ttwu_runnable()    -- old rq, unavoidable, see comment there;
 *  - ttwu_queue()       -- new rq, for enqueue of the task;
 *  - psi_ttwu_dequeue() -- much sadness :-( accounting will kill us.
 *
 * As a consequence we race really badly with just about everything. See the
 * many memory barriers and their comments for details.
 *
 * Return: %true if @p->state changes (an actual wakeup was done),
 *     %false otherwise.
 */
static int
try_to_wake_up(struct task_struct *p, unsigned int state,
               int wake_flags)
{
    unsigned long flags;
    int cpu, success = 0;

    preempt_disable();
    if (p == current) {
        /*
         * We're waking current, this means 'p->on_rq' and 'task_cpu(p)
         * == smp_processor_id()'. Together this means we can special
         * case the whole 'p->on_rq && ttwu_runnable()' case below
         * without taking any locks.
         *
         * In particular:
         *  - we rely on Program-Order guarantees for all the ordering,
         *  - we're serialized against set_special_state() by virtue of
         *    it disabling IRQs (this allows not taking ->pi_lock).
         */
        if (!ttwu_state_match(p, state, &success))
            goto out;

        WRITE_ONCE(p->__state, TASK_RUNNING);
        goto out;
    }

    /*
     * If we are going to wake up a thread waiting for CONDITION we
     * need to ensure that CONDITION=1 done by the caller can not be
     * reordered with p->state check below. This pairs with smp_store_mb()
     * in set_current_state() that the waiting thread does.
     */
    raw_spin_lock_irqsave(&p->pi_lock, flags);
    smp_mb__after_spinlock();
    if (!ttwu_state_match(p, state, &success))
        goto unlock;

    /*
     * Ensure we load p->on_rq _after_ p->state, otherwise it would
     * be possible to, falsely, observe p->on_rq == 0 and get stuck
     * in smp_cond_load_acquire() below.
     *
     * sched_ttwu_pending()         try_to_wake_up()
     *   STORE p->on_rq = 1           LOAD p->state
     *   UNLOCK rq->lock
     *
     * __schedule() (switch to task 'p')
     *   LOCK rq->lock            smp_rmb();
     *   smp_mb__after_spinlock();
     *   UNLOCK rq->lock
     *
     * [task p]
     *   STORE p->state = UNINTERRUPTIBLE     LOAD p->on_rq
     *
     * Pairs with the LOCK+smp_mb__after_spinlock() on rq->lock in
     * __schedule().  See the comment for smp_mb__after_spinlock().
     *
     * A similar smb_rmb() lives in try_invoke_on_locked_down_task().
     */
    smp_rmb();
    if (READ_ONCE(p->on_rq) && ttwu_runnable(p, wake_flags))
        goto unlock;

    panic("%s: NO implementation!\n", __func__);

 unlock:
    raw_spin_unlock_irqrestore(&p->pi_lock, flags);
 out:
    if (success)
        ttwu_stat(p, task_cpu(p), wake_flags);
    preempt_enable();

    return success;
}

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
    return try_to_wake_up(p, TASK_NORMAL, 0);
}
EXPORT_SYMBOL(wake_up_process);

static inline void sched_submit_work(struct task_struct *tsk)
{
    unsigned int task_flags;

    if (task_is_running(tsk))
        return;

    task_flags = tsk->flags;
    /*
     * If a worker goes to sleep, notify and ask workqueue whether it
     * wants to wake up a task to maintain concurrency.
     */
    if (task_flags & (PF_WQ_WORKER | PF_IO_WORKER)) {
#if 0
        if (task_flags & PF_WQ_WORKER)
            wq_worker_sleeping(tsk);
        else
            io_wq_worker_sleeping(tsk);
#endif
        panic("%s: (PF_WQ_WORKER | PF_IO_WORKER)!\n", __func__);
    }

    if (tsk_is_pi_blocked(tsk))
        return;

    /*
     * If we are going to sleep and we have plugged IO queued,
     * make sure to submit it to avoid deadlocks.
     */
    blk_flush_plug(tsk->plug, true);
}

static void sched_update_worker(struct task_struct *tsk)
{
    if (tsk->flags & (PF_WQ_WORKER | PF_IO_WORKER)) {
        if (tsk->flags & PF_WQ_WORKER)
            wq_worker_running(tsk);
        else
            io_wq_worker_running(tsk);
    }
}

/*
 * Constants for the sched_mode argument of __schedule().
 *
 * The mode argument allows RT enabled kernels to differentiate a
 * preemption from blocking on an 'sleeping' spin/rwlock. Note that
 * SM_MASK_PREEMPT for !RT has all bits set, which allows the compiler to
 * optimize the AND operation out and just check for zero.
 */
#define SM_NONE             0x0
#define SM_PREEMPT          0x1
#define SM_RTLOCK_WAIT      0x2

static void put_prev_task_balance(struct rq *rq,
                                  struct task_struct *prev,
                                  struct rq_flags *rf)
{
    const struct sched_class *class;
    /*
     * We must do the balancing pass before put_prev_task(), such
     * that when we release the rq->lock the task is in the same
     * state as before we took rq->lock.
     *
     * We can terminate the balance pass as soon as we know there is
     * a runnable task of @class priority or higher.
     */
    for_class_range(class, prev->sched_class, &idle_sched_class) {
        if (class->balance(rq, prev, rf))
            break;
    }

    put_prev_task(rq, prev);
}

/*
 * Pick up the highest-prio task:
 */
static inline struct task_struct *
__pick_next_task(struct rq *rq, struct task_struct *prev,
                 struct rq_flags *rf)
{
    const struct sched_class *class;
    struct task_struct *p;

    put_prev_task_balance(rq, prev, rf);

    for_each_class(class) {
        p = class->pick_next_task(rq);
        if (p)
            return p;
    }

    BUG(); /* The idle class should always have a runnable task. */
}

static struct task_struct *
pick_next_task(struct rq *rq, struct task_struct *prev,
               struct rq_flags *rf)
{
    return __pick_next_task(rq, prev, rf);
}

static void
__fire_sched_out_preempt_notifiers(struct task_struct *curr,
                                   struct task_struct *next)
{
    struct preempt_notifier *notifier;

    hlist_for_each_entry(notifier, &curr->preempt_notifiers, link)
        notifier->ops->sched_out(notifier, next);
}

static __always_inline void
fire_sched_out_preempt_notifiers(struct task_struct *curr,
                                 struct task_struct *next)
{
    if (static_branch_unlikely(&preempt_notifier_key))
        __fire_sched_out_preempt_notifiers(curr, next);
}

/**
 * prepare_task_switch - prepare to switch tasks
 * @rq: the runqueue preparing to switch
 * @prev: the current task that is being switched out
 * @next: the task we are going to switch to.
 *
 * This is called with the rq lock held and interrupts off. It must
 * be paired with a subsequent finish_task_switch after the context
 * switch.
 *
 * prepare_task_switch sets up locking and calls architecture specific
 * hooks.
 */
static inline void
prepare_task_switch(struct rq *rq, struct task_struct *prev,
                    struct task_struct *next)
{
    rseq_preempt(prev);
    fire_sched_out_preempt_notifiers(prev, next);
    prepare_task(next);
}

static inline void
prepare_lock_switch(struct rq *rq, struct task_struct *next,
                    struct rq_flags *rf)
{
    /*
     * Since the runqueue lock will be released by the next
     * task (which is an invalid locking op but in the case
     * of the scheduler it's an obvious special-case), so we
     * do an early lockdep release here:
     */
    rq_unpin_lock(rq, rf);
}

/*
 * context_switch - switch to the new MM and the new thread's register state.
 */
static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev,
               struct task_struct *next, struct rq_flags *rf)
{
    prepare_task_switch(rq, prev, next);

    /*
     * kernel -> kernel   lazy + transfer active
     *   user -> kernel   lazy + mmgrab() active
     *
     * kernel ->   user   switch + mmdrop() active
     *   user ->   user   switch
     */
    if (!next->mm) {                            // to kernel
        next->active_mm = prev->active_mm;
        if (prev->mm)                           // from user
            mmgrab(prev->active_mm);
        else
            prev->active_mm = NULL;
    } else {                                    // to user
        panic("%s: next->mm!\n", __func__);
    }

    rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);

    prepare_lock_switch(rq, next, rf);

    /* Here we just switch the register state and the stack. */
    switch_to(prev, next, prev);
    barrier();

    return finish_task_switch(prev);
}

static void do_balance_callbacks(struct rq *rq,
                                 struct callback_head *head)
{
    void (*func)(struct rq *rq);
    struct callback_head *next;

    while (head) {
        func = (void (*)(struct rq *))head->func;
        next = head->next;
        head->next = NULL;
        head = next;

        func(rq);
    }
}

static inline
struct callback_head *splice_balance_callbacks(struct rq *rq)
{
    struct callback_head *head = rq->balance_callback;

    if (head)
        rq->balance_callback = NULL;

    return head;
}

static void __balance_callbacks(struct rq *rq)
{
    do_balance_callbacks(rq, splice_balance_callbacks(rq));
}

static void
__do_set_cpus_allowed(struct task_struct *p,
                      const struct cpumask *new_mask,
                      u32 flags);

static int __set_cpus_allowed_ptr(struct task_struct *p,
                                  const struct cpumask *new_mask,
                                  u32 flags);

static void migrate_disable_switch(struct rq *rq, struct task_struct *p)
{
    printk("%s: 1\n", __func__);
    if (likely(!p->migration_disabled))
        return;

    printk("%s: 2\n", __func__);
    if (p->cpus_ptr != &p->cpus_mask)
        return;

    printk("%s: 3\n", __func__);
    /*
     * Violates locking rules! see comment in __do_set_cpus_allowed().
     */
    __do_set_cpus_allowed(p, cpumask_of(rq->cpu), SCA_MIGRATE_DISABLE);
}

/*
 * __schedule() is the main scheduler function.
 *
 * The main means of driving the scheduler and thus entering this function are:
 *
 *   1. Explicit blocking: mutex, semaphore, waitqueue, etc.
 *
 *   2. TIF_NEED_RESCHED flag is checked on interrupt and userspace return
 *      paths. For example, see arch/x86/entry_64.S.
 *
 *      To drive preemption between tasks, the scheduler sets the flag in timer
 *      interrupt handler scheduler_tick().
 *
 *   3. Wakeups don't really cause entry into schedule(). They add a
 *      task to the run-queue and that's it.
 *
 *      Now, if the new task added to the run-queue preempts the current
 *      task, then the wakeup sets TIF_NEED_RESCHED and schedule() gets
 *      called on the nearest possible occasion:
 *
 *       - If the kernel is preemptible (CONFIG_PREEMPTION=y):
 *
 *         - in syscall or exception context, at the next outmost
 *           preempt_enable(). (this might be as soon as the wake_up()'s
 *           spin_unlock()!)
 *
 *         - in IRQ context, return from interrupt-handler to
 *           preemptible context
 *
 *       - If the kernel is not preemptible (CONFIG_PREEMPTION is not set)
 *         then at the next:
 *
 *          - cond_resched() call
 *          - explicit schedule() call
 *          - return from syscall or exception to user-space
 *          - return from interrupt-handler to user-space
 *
 * WARNING: must be called with preemption disabled!
 */
static void __sched notrace __schedule(unsigned int sched_mode)
{
    int cpu;
    struct rq *rq;
    struct rq_flags rf;
    unsigned long prev_state;
    unsigned long *switch_count;
    struct task_struct *prev, *next;

    cpu = smp_processor_id();
    rq = cpu_rq(cpu);
    prev = rq->curr;

    local_irq_disable();
    //rcu_note_context_switch(!!sched_mode);

    /*
     * Make sure that signal_pending_state()->signal_pending() below
     * can't be reordered with __set_current_state(TASK_INTERRUPTIBLE)
     * done by the caller to avoid the race with signal_wake_up():
     *
     * __set_current_state(@state)      signal_wake_up()
     * schedule()                 set_tsk_thread_flag(p, TIF_SIGPENDING)
     *                    wake_up_state(p, state)
     *   LOCK rq->lock              LOCK p->pi_state
     *   smp_mb__after_spinlock()           smp_mb__after_spinlock()
     *     if (signal_pending_state())      if (p->state & @state)
     *
     * Also, the membarrier system call requires a full memory barrier
     * after coming from user-space, before storing to rq->curr.
     */
    rq_lock(rq, &rf);
    smp_mb__after_spinlock();

    next = pick_next_task(rq, prev, &rf);

    clear_tsk_need_resched(prev);

    if (likely(prev != next)) {
        rq->nr_switches++;
        /*
         * RCU users of rcu_dereference(rq->curr) may not see
         * changes to task_struct made by pick_next_task().
         */
        RCU_INIT_POINTER(rq->curr, next);
        /*
         * The membarrier system call requires each architecture
         * to have a full memory barrier after updating
         * rq->curr, before returning to user-space.
         *
         * Here are the schemes providing that barrier on the
         * various architectures:
         * - mm ? switch_mm() : mmdrop() for x86, s390, sparc, PowerPC.
         *   switch_mm() rely on membarrier_arch_switch_mm() on PowerPC.
         * - finish_lock_switch() for weakly-ordered
         *   architectures where spin_unlock is a full barrier,
         * - switch_to() for arm64 (weakly-ordered, spin_unlock
         *   is a RELEASE barrier),
         */
        ++*switch_count;

        migrate_disable_switch(rq, prev);

        /* Also unlocks the rq: */
        rq = context_switch(rq, prev, next, &rf);
    } else {
        rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);

        rq_unpin_lock(rq, &rf);
        __balance_callbacks(rq);
        raw_spin_rq_unlock_irq(rq);
    }
}

asmlinkage __visible void __sched schedule(void)
{
    struct task_struct *tsk = current;

    sched_submit_work(tsk);
    do {
        preempt_disable();
        __schedule(SM_NONE);
        sched_preempt_enable_no_resched();
    } while (need_resched());
    sched_update_worker(tsk);
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
static void __sched_fork(unsigned long clone_flags,
                         struct task_struct *p)
{
    p->on_rq            = 0;

    p->se.on_rq         = 0;
    p->se.exec_start        = 0;
    p->se.sum_exec_runtime      = 0;
    p->se.prev_sum_exec_runtime = 0;
    p->se.nr_migrations     = 0;
    p->se.vruntime          = 0;
    INIT_LIST_HEAD(&p->se.group_node);

    p->se.cfs_rq            = NULL;

    RB_CLEAR_NODE(&p->dl.rb_node);
    init_dl_task_timer(&p->dl);
    init_dl_inactive_task_timer(&p->dl);
    __dl_clear_params(p);

    INIT_LIST_HEAD(&p->rt.run_list);
    p->rt.timeout       = 0;
    p->rt.time_slice    = sched_rr_timeslice;
    p->rt.on_rq         = 0;
    p->rt.on_list       = 0;

    INIT_HLIST_HEAD(&p->preempt_notifiers);

    p->capture_control = NULL;
    p->wake_entry.u_flags = CSD_TYPE_TTWU;
    p->migration_pending = NULL;
}

/* Give new sched_entity start runnable values to heavy its load in infant time */
void init_entity_runnable_average(struct sched_entity *se)
{
    struct sched_avg *sa = &se->avg;

    memset(sa, 0, sizeof(*sa));

    /*
     * Tasks are initialized with full load to be seen as heavy tasks until
     * they get a chance to stabilize to their real load level.
     * Group entities are initialized with zero load to reflect the fact that
     * nothing has been attached to the task group yet.
     */
    if (entity_is_task(se))
        sa->load_avg = scale_load_down(se->load.weight);

    /* when this task enqueue'ed, it will contribute to its cfs_rq's load_avg */
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

    /*
     * Make sure we do not leak PI boosting priority to the child.
     */
    p->prio = current->normal_prio;

    /*
     * Revert to default priority/policy on fork if requested.
     */
    if (unlikely(p->sched_reset_on_fork)) {
        panic("%s: sched_reset_on_fork!\n", __func__);
    }

    pr_info("%s: prio(%d)\n", __func__, p->prio);
    if (dl_prio(p->prio))
        return -EAGAIN;
    else if (rt_prio(p->prio))
        p->sched_class = &rt_sched_class;
    else
        p->sched_class = &fair_sched_class;

    init_entity_runnable_average(&p->se);

    p->on_cpu = 0;

    init_task_preempt_count(p);

    plist_node_init(&p->pushable_tasks, MAX_PRIO);
    RB_CLEAR_NODE(&p->pushable_dl_tasks);

    return 0;
}

static inline void finish_task(struct task_struct *prev)
{
    /*
     * This must be the very last reference to @prev from this CPU. After
     * p->on_cpu is cleared, the task can be moved to a different CPU. We
     * must ensure this doesn't happen until the switch is completely
     * finished.
     *
     * In particular, the load of prev->state in finish_task_switch() must
     * happen before this.
     *
     * Pairs with the smp_cond_load_acquire() in try_to_wake_up().
     */
    smp_store_release(&prev->on_cpu, 0);
}

static inline void finish_lock_switch(struct rq *rq)
{
    /*
     * If we are tracking spinlock dependencies then we have to
     * fix up the runqueue lock - which gets 'carried over' from
     * prev into current:
     */
    __balance_callbacks(rq);
    raw_spin_rq_unlock_irq(rq);
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
    prev_state = READ_ONCE(prev->__state);
    finish_task(prev);
    finish_lock_switch(rq);

    //fire_sched_in_preempt_notifiers(current);
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
        mmdrop_sched(mm);
    }
    if (unlikely(prev_state == TASK_DEAD)) {
        if (prev->sched_class->task_dead)
            prev->sched_class->task_dead(prev);

        /* Task is done with its stack. */
        put_task_stack(prev);

        put_task_struct_rcu_user(prev);
    }

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
 * Per-CPU kthreads are allowed to run on !active && online CPUs, see
 * __set_cpus_allowed_ptr() and select_fallback_rq().
 */
static inline bool is_cpu_allowed(struct task_struct *p, int cpu)
{
    /* When not in the task's cpumask, no point in looking further. */
    if (!cpumask_test_cpu(cpu, p->cpus_ptr))
        return false;

    /* migrate_disabled() must be allowed to finish. */
    if (is_migration_disabled(p))
        return cpu_online(cpu);

    /* Non kernel threads are not allowed during either online or offline. */
    if (!(p->flags & PF_KTHREAD))
        return cpu_active(cpu) && task_cpu_possible(cpu, p);

#if 0
    /* KTHREAD_IS_PER_CPU is always allowed. */
    if (kthread_is_per_cpu(p))
        return cpu_online(cpu);
#endif

    /* Regular kernel threads don't get to stay during offline. */
    if (cpu_dying(cpu))
        return false;

    /* But are allowed during online. */
    return cpu_online(cpu);
}

/*
 * The caller (fork, wakeup) owns p->pi_lock, ->cpus_ptr is stable.
 */
static inline
int select_task_rq(struct task_struct *p, int cpu, int wake_flags)
{
    if (p->nr_cpus_allowed > 1 && !is_migration_disabled(p))
        cpu = p->sched_class->select_task_rq(p, cpu, wake_flags);
    else
        cpu = cpumask_any(p->cpus_ptr);

    /*
     * In order not to call set_task_cpu() on a blocking task we need
     * to rely on ttwu() to place the task on a valid ->cpus_ptr
     * CPU.
     *
     * Since this is common to all placement strategies, this lives here.
     *
     * [ this allows ->select_task() to simply return task_cpu(p) and
     *   not worry about this generic constraint ]
     */
    if (unlikely(!is_cpu_allowed(p, cpu))) {
        panic("%s: !is_cpu_allowed!\n", __func__);
        //cpu = select_fallback_rq(task_cpu(p), p);
    }

    return cpu;
}

/*
 * __task_rq_lock - lock the rq @p resides on.
 */
struct rq *__task_rq_lock(struct task_struct *p, struct rq_flags *rf)
    __acquires(rq->lock)
{
    struct rq *rq;

    for (;;) {
        rq = task_rq(p);
        raw_spin_rq_lock(rq);
        if (likely(rq == task_rq(p) && !task_on_rq_migrating(p))) {
            //rq_pin_lock(rq, rf);
            return rq;
        }
        raw_spin_rq_unlock(rq);

        while (unlikely(task_on_rq_migrating(p)))
            cpu_relax();
    }
}

static inline void sched_core_enqueue(struct rq *rq,
                                      struct task_struct *p)
{
}
static inline void
sched_core_dequeue(struct rq *rq, struct task_struct *p, int flags)
{
}

static void update_rq_clock_task(struct rq *rq, s64 delta)
{
/*
 * In theory, the compile should just see 0 here, and optimize out the call
 * to sched_rt_avg_update. But I don't trust it...
 */
    s64 __maybe_unused steal = 0, irq_delta = 0;

    rq->clock_task += delta;

    update_rq_clock_pelt(rq, delta);
}

void update_rq_clock(struct rq *rq)
{
    s64 delta;

    if (rq->clock_update_flags & RQCF_ACT_SKIP)
        return;

    delta = sched_clock_cpu(cpu_of(rq)) - rq->clock;
    if (delta < 0)
        return;
    rq->clock += delta;
    update_rq_clock_task(rq, delta);
}

static inline void enqueue_task(struct rq *rq, struct task_struct *p, int flags)
{
    if (!(flags & ENQUEUE_NOCLOCK))
        update_rq_clock(rq);

    if (!(flags & ENQUEUE_RESTORE)) {
        sched_info_enqueue(rq, p);
    }

    p->sched_class->enqueue_task(rq, p, flags);
}

void activate_task(struct rq *rq, struct task_struct *p, int flags)
{
    enqueue_task(rq, p, flags);

    p->on_rq = TASK_ON_RQ_QUEUED;
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
#endif
    __set_task_cpu(p, select_task_rq(p, task_cpu(p), WF_FORK));

    rq = __task_rq_lock(p, &rf);
    update_rq_clock(rq);
#if 0
    post_init_entity_util_avg(p);
#endif

    activate_task(rq, p, ENQUEUE_NOCLOCK);
    check_preempt_curr(rq, p, WF_FORK);
    if (p->sched_class->task_woken) {
        panic("%s: no task_woken for sched_class.\n", __func__);
    }
    task_rq_unlock(rq, p, &rf);
}

void raw_spin_rq_lock_nested(struct rq *rq, int subclass)
{
    raw_spinlock_t *lock;

    /* Matches synchronize_rcu() in __sched_core_enable() */
    preempt_disable();
    raw_spin_lock_nested(&rq->__lock, subclass);
    /* preempt_count *MUST* be > 1 */
    preempt_enable_no_resched();
}

void raw_spin_rq_unlock(struct rq *rq)
{
    raw_spin_unlock(rq_lockp(rq));
}

/*
 * Default task group.
 * Every task in system belongs to this group at bootup.
 */
struct task_group root_task_group;
LIST_HEAD(task_groups);

/* Cacheline aligned slab cache for task_group */
static struct kmem_cache *task_group_cache __read_mostly;

/**
 * init_idle - set up an idle thread for a given CPU
 * @idle: task in question
 * @cpu: CPU the idle task belongs to
 *
 * NOTE: this function does not set the idle thread's NEED_RESCHED
 * flag, to make booting more robust.
 */
void __init init_idle(struct task_struct *idle, int cpu)
{
    struct rq *rq = cpu_rq(cpu);
    unsigned long flags;

    __sched_fork(0, idle);

    raw_spin_lock_irqsave(&idle->pi_lock, flags);
    raw_spin_rq_lock(rq);

    idle->__state = TASK_RUNNING;
#if 0
    idle->se.exec_start = sched_clock();
#endif
    /*
     * PF_KTHREAD should already be set at this point; regardless, make it
     * look like a proper per-CPU kthread.
     */
    idle->flags |= PF_IDLE | PF_KTHREAD | PF_NO_SETAFFINITY;
#if 0
    kthread_set_per_cpu(idle, cpu);
#endif

#if 0
    /*
     * It's possible that init_idle() gets called multiple times on a task,
     * in that case do_set_cpus_allowed() will not do the right thing.
     *
     * And since this is boot we can forgo the serialization.
     */
    set_cpus_allowed_common(idle, cpumask_of(cpu), 0);
#endif

    /*
     * We're having a chicken and egg problem, even though we are
     * holding rq->lock, the CPU isn't yet set to this CPU so the
     * lockdep check in task_group() will fail.
     *
     * Similar case to sched_fork(). / Alternatively we could
     * use task_rq_lock() here and obtain the other rq->lock.
     *
     * Silence PROVE_RCU
     */
    rcu_read_lock();
    __set_task_cpu(idle, cpu);
    rcu_read_unlock();

    rq->idle = idle;
    rcu_assign_pointer(rq->curr, idle);
    idle->on_rq = TASK_ON_RQ_QUEUED;
    idle->on_cpu = 1;
    raw_spin_rq_unlock(rq);
    raw_spin_unlock_irqrestore(&idle->pi_lock, flags);

    /* Set the preempt count _outside_ the spinlocks! */
    init_idle_preempt_count(idle, cpu);

    /*
     * The idle tasks have their own, simple scheduling class:
     */
    idle->sched_class = &idle_sched_class;
    sprintf(idle->comm, "%s/%d", INIT_TASK_COMM, cpu);

    printk("++++++ %s: ref(%d)\n", __func__, rq->__lock.raw_lock.lock);
}

static void nohz_csd_func(void *info)
{
    panic("%s: NO implementation!", __func__);
}

static void __hrtick_restart(struct rq *rq)
{
    struct hrtimer *timer = &rq->hrtick_timer;
    ktime_t time = rq->hrtick_time;

    hrtimer_start(timer, time, HRTIMER_MODE_ABS_PINNED_HARD);
}

/*
 * called from hardirq (IPI) context
 */
static void __hrtick_start(void *arg)
{
    struct rq *rq = arg;
    struct rq_flags rf;

    rq_lock(rq, &rf);
    __hrtick_restart(rq);
    rq_unlock(rq, &rf);
}

/*
 * High-resolution timer tick.
 * Runs from hardirq context with interrupts disabled.
 */
static enum hrtimer_restart hrtick(struct hrtimer *timer)
{
    struct rq *rq = container_of(timer, struct rq, hrtick_timer);
    struct rq_flags rf;

    WARN_ON_ONCE(cpu_of(rq) != smp_processor_id());

    rq_lock(rq, &rf);
    update_rq_clock(rq);
    rq->curr->sched_class->task_tick(rq, rq->curr, 1);
    rq_unlock(rq, &rf);

    return HRTIMER_NORESTART;
}

static void hrtick_rq_init(struct rq *rq)
{
    INIT_CSD(&rq->hrtick_csd, __hrtick_start, rq);
    hrtimer_init(&rq->hrtick_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_HARD);
    rq->hrtick_timer.function = hrtick;
}

static void set_load_weight(struct task_struct *p, bool update_load)
{
    int prio = p->static_prio - MAX_RT_PRIO;
    struct load_weight *load = &p->se.load;

    /*
     * SCHED_IDLE tasks get minimal weight:
     */
    if (task_has_idle_policy(p)) {
        load->weight = scale_load(WEIGHT_IDLEPRIO);
        load->inv_weight = WMULT_IDLEPRIO;
        return;
    }

    /*
     * SCHED_OTHER tasks have to update their load when changing their
     * weight
     */
    if (update_load && p->sched_class == &fair_sched_class) {
        reweight_task(p, prio);
    } else {
        load->weight = scale_load(sched_prio_to_weight[prio]);
        load->inv_weight = sched_prio_to_wmult[prio];
    }
}

static void balance_push_set(int cpu, bool on)
{
    struct rq *rq = cpu_rq(cpu);
    struct rq_flags rf;

    rq_lock_irqsave(rq, &rf);
    if (on) {
        WARN_ON_ONCE(rq->balance_callback);
        rq->balance_callback = &balance_push_callback;
    } else if (rq->balance_callback == &balance_push_callback) {
        rq->balance_callback = NULL;
    }
    rq_unlock_irqrestore(rq, &rf);
}

void __init sched_init(void)
{
    int i;
    unsigned long ptr = 0;

    /* Make sure the linker didn't screw up */
    BUG_ON(&idle_sched_class + 1 != &fair_sched_class ||
           &fair_sched_class + 1 != &rt_sched_class ||
           &rt_sched_class + 1   != &dl_sched_class);
    BUG_ON(&dl_sched_class + 1   != &stop_sched_class);

    wait_bit_init();

    ptr += 2 * nr_cpu_ids * sizeof(void **);

    if (ptr) {
        ptr = (unsigned long)kzalloc(ptr, GFP_NOWAIT);

        root_task_group.se = (struct sched_entity **)ptr;
        ptr += nr_cpu_ids * sizeof(void **);

        root_task_group.cfs_rq = (struct cfs_rq **)ptr;
        ptr += nr_cpu_ids * sizeof(void **);

        root_task_group.shares = ROOT_TASK_GROUP_LOAD;
#if 0
        init_cfs_bandwidth(&root_task_group.cfs_bandwidth);
#endif
    }

#if 0
    init_rt_bandwidth(&def_rt_bandwidth,
                      global_rt_period(), global_rt_runtime());
#endif

    init_defrootdomain();

    task_group_cache = KMEM_CACHE(task_group, 0);

    list_add(&root_task_group.list, &task_groups);
    INIT_LIST_HEAD(&root_task_group.children);
    INIT_LIST_HEAD(&root_task_group.siblings);

    for_each_possible_cpu(i) {
        struct rq *rq;

        rq = cpu_rq(i);
        raw_spin_lock_init(&rq->__lock);
        rq->nr_running = 0;
        rq->calc_load_active = 0;
        rq->calc_load_update = jiffies + LOAD_FREQ;
        init_cfs_rq(&rq->cfs);
        init_rt_rq(&rq->rt);
        init_dl_rq(&rq->dl);

        INIT_LIST_HEAD(&rq->leaf_cfs_rq_list);
        rq->tmp_alone_branch = &rq->leaf_cfs_rq_list;
        /*
         * How much CPU bandwidth does root_task_group get?
         *
         * In case of task-groups formed thr' the cgroup filesystem, it
         * gets 100% of the CPU resources in the system. This overall
         * system CPU resource is divided among the tasks of
         * root_task_group and its child task-groups in a fair manner,
         * based on each entity's (task or task-group's) weight
         * (se->load.weight).
         *
         * In other words, if root_task_group has 10 tasks of weight
         * 1024) and two child groups A0 and A1 (of weight 1024 each),
         * then A0's share of the CPU resource is:
         *
         *  A0's bandwidth = 1024 / (10*1024 + 1024 + 1024) = 8.33%
         *
         * We achieve this by letting root_task_group's tasks sit
         * directly in rq->cfs (i.e root_task_group->se[] = NULL).
         */
        init_tg_cfs_entry(&root_task_group, &rq->cfs, NULL, i, NULL);

        rq->rt.rt_runtime = def_rt_bandwidth.rt_runtime;

        rq->sd = NULL;
        rq->rd = NULL;
        rq->cpu_capacity = rq->cpu_capacity_orig = SCHED_CAPACITY_SCALE;
        rq->balance_callback = &balance_push_callback;
        rq->active_balance = 0;
        rq->next_balance = jiffies;
        rq->push_cpu = 0;
        rq->cpu = i;
        rq->online = 0;
        rq->idle_stamp = 0;
        rq->avg_idle = 2*sysctl_sched_migration_cost;
        rq->wake_stamp = jiffies;
        rq->wake_avg_idle = rq->avg_idle;
        rq->max_idle_balance_cost = sysctl_sched_migration_cost;

        INIT_LIST_HEAD(&rq->cfs_tasks);

        rq_attach_root(rq, &def_root_domain);
        rq->last_blocked_load_update_tick = jiffies;
        atomic_set(&rq->nohz_flags, 0);

        INIT_CSD(&rq->nohz_csd, nohz_csd_func, rq);
        rcuwait_init(&rq->hotplug_wait);

        hrtick_rq_init(rq);
        atomic_set(&rq->nr_iowait, 0);
    }

    set_load_weight(&init_task, false);

    /*
     * The boot idle thread does lazy MMU switching as well:
     */
    mmgrab(&init_mm);

    /*
     * The idle task doesn't need the kthread struct to function, but it
     * is dressed up as a per-CPU kthread and thus needs to play the part
     * if we want to avoid special-casing it in code that deals with per-CPU
     * kthreads.
     */
    WARN_ON(!set_kthread_struct(current));

    /*
     * Make us the idle thread. Technically, schedule() should not be
     * called from this thread, however somewhere below it might be,
     * but because we are the idle thread, we just pick up running again
     * when this runqueue becomes "idle".
     */
    init_idle(current, smp_processor_id());

    calc_load_update = jiffies + LOAD_FREQ;

    idle_thread_set_boot_cpu();
    balance_push_set(smp_processor_id(), false);

    //init_sched_fair_class();

    scheduler_running = 1;
}

int default_wake_function(wait_queue_entry_t *curr,
                          unsigned mode, int wake_flags, void *key)
{
    return try_to_wake_up(curr->private, mode, wake_flags);
}
EXPORT_SYMBOL(default_wake_function);

int io_schedule_prepare(void)
{
    int old_iowait = current->in_iowait;

    current->in_iowait = 1;
    blk_flush_plug(current->plug, true);
    return old_iowait;
}

void io_schedule_finish(int token)
{
    current->in_iowait = token;
}

void __sched io_schedule(void)
{
    int token;

    token = io_schedule_prepare();
    schedule();
    io_schedule_finish(token);
}
EXPORT_SYMBOL(io_schedule);

/*
 * Ensure we only run per-cpu kthreads once the CPU goes !active.
 *
 * This is enabled below SCHED_AP_ACTIVE; when !cpu_active(), but only
 * effective when the hotplug motion is down.
 */
static void balance_push(struct rq *rq)
{
    panic("%s: NOT-implemented!\n", __func__);
}

void set_rq_online(struct rq *rq)
{
    if (!rq->online) {
        const struct sched_class *class;

        cpumask_set_cpu(rq->cpu, rq->rd->online);
        rq->online = 1;

        for_each_class(class) {
            if (class->rq_online)
                class->rq_online(rq);
        }
    }
}

void set_rq_offline(struct rq *rq)
{
    if (rq->online) {
        const struct sched_class *class;

        for_each_class(class) {
            if (class->rq_offline)
                class->rq_offline(rq);
        }

        cpumask_clear_cpu(rq->cpu, rq->rd->online);
        rq->online = 0;
    }
}

/*
 * wait_task_inactive - wait for a thread to unschedule.
 *
 * If @match_state is nonzero, it's the @p->state value just checked and
 * not expected to change.  If it changes, i.e. @p might have woken up,
 * then return zero.  When we succeed in waiting for @p to be off its CPU,
 * we return a positive number (its total switch count).  If a second call
 * a short while later returns the same number, the caller can be sure that
 * @p has remained unscheduled the whole time.
 *
 * The caller must ensure that the task *will* unschedule sometime soon,
 * else this function might spin for a *long* time. This function can't
 * be called with interrupts off, or it may introduce deadlock with
 * smp_call_function() if an IPI is sent by the same process we are
 * waiting to become inactive.
 */
unsigned long wait_task_inactive(struct task_struct *p,
                                 unsigned int match_state)
{
    int running, queued;
    struct rq_flags rf;
    unsigned long ncsw;
    struct rq *rq;

    panic("%s: NOT-implemented!\n", __func__);
}

static inline void uclamp_rq_inc(struct rq *rq, struct task_struct *p)
{ }
static inline void uclamp_rq_dec(struct rq *rq, struct task_struct *p)
{ }
static inline int uclamp_validate(struct task_struct *p,
                                  const struct sched_attr *attr)
{
    return -EOPNOTSUPP;
}
static void __setscheduler_uclamp(struct task_struct *p,
                                  const struct sched_attr *attr)
{ }
static inline void uclamp_fork(struct task_struct *p) { }
static inline void uclamp_post_fork(struct task_struct *p) { }
static inline void init_uclamp(void) { }

static inline void dequeue_task(struct rq *rq, struct task_struct *p,
                                int flags)
{
    if (sched_core_enabled(rq))
        sched_core_dequeue(rq, p, flags);

    if (!(flags & DEQUEUE_NOCLOCK))
        update_rq_clock(rq);

    if (!(flags & DEQUEUE_SAVE)) {
        sched_info_dequeue(rq, p);
        psi_dequeue(p, flags & DEQUEUE_SLEEP);
    }

    uclamp_rq_dec(rq, p);
    p->sched_class->dequeue_task(rq, p, flags);
}

static void
__do_set_cpus_allowed(struct task_struct *p,
                      const struct cpumask *new_mask,
                      u32 flags)
{
    struct rq *rq = task_rq(p);
    bool queued, running;

    /*
     * This here violates the locking rules for affinity, since we're only
     * supposed to change these variables while holding both rq->lock and
     * p->pi_lock.
     *
     * HOWEVER, it magically works, because ttwu() is the only code that
     * accesses these variables under p->pi_lock and only does so after
     * smp_cond_load_acquire(&p->on_cpu, !VAL), and we're in __schedule()
     * before finish_task().
     *
     * XXX do further audits, this smells like something putrid.
     */
    if (flags & SCA_MIGRATE_DISABLE)
        SCHED_WARN_ON(!p->on_cpu);

    queued = task_on_rq_queued(p);
    running = task_current(rq, p);

    if (queued) {
        /*
         * Because __kthread_bind() calls this on blocked tasks without
         * holding rq->lock.
         */
        dequeue_task(rq, p, DEQUEUE_SAVE | DEQUEUE_NOCLOCK);
    }
    if (running)
        put_prev_task(rq, p);

    pr_info("%s: 1 sched_class(%lx)\n", __func__, p->sched_class);
    p->sched_class->set_cpus_allowed(p, new_mask, flags);
    pr_info("%s: 2\n", __func__);

    if (queued)
        enqueue_task(rq, p, ENQUEUE_RESTORE | ENQUEUE_NOCLOCK);
    if (running)
        set_next_task(rq, p);
}

void do_set_cpus_allowed(struct task_struct *p,
                         const struct cpumask *new_mask)
{
    __do_set_cpus_allowed(p, new_mask, 0);
}

int push_cpu_stop(void *arg)
{
    panic("%s: NOT-implemented!\n", __func__);
}

/*
 * This function is wildly self concurrent; here be dragons.
 *
 *
 * When given a valid mask, __set_cpus_allowed_ptr() must block until the
 * designated task is enqueued on an allowed CPU. If that task is currently
 * running, we have to kick it out using the CPU stopper.
 *
 * Migrate-Disable comes along and tramples all over our nice sandcastle.
 * Consider:
 *
 *     Initial conditions: P0->cpus_mask = [0, 1]
 *
 *     P0@CPU0                  P1
 *
 *     migrate_disable();
 *     <preempted>
 *                              set_cpus_allowed_ptr(P0, [1]);
 *
 * P1 *cannot* return from this set_cpus_allowed_ptr() call until P0 executes
 * its outermost migrate_enable() (i.e. it exits its Migrate-Disable region).
 * This means we need the following scheme:
 *
 *     P0@CPU0                  P1
 *
 *     migrate_disable();
 *     <preempted>
 *                              set_cpus_allowed_ptr(P0, [1]);
 *                                <blocks>
 *     <resumes>
 *     migrate_enable();
 *       __set_cpus_allowed_ptr();
 *       <wakes local stopper>
 *                         `--> <woken on migration completion>
 *
 * Now the fun stuff: there may be several P1-like tasks, i.e. multiple
 * concurrent set_cpus_allowed_ptr(P0, [*]) calls. CPU affinity changes of any
 * task p are serialized by p->pi_lock, which we can leverage: the one that
 * should come into effect at the end of the Migrate-Disable region is the last
 * one. This means we only need to track a single cpumask (i.e. p->cpus_mask),
 * but we still need to properly signal those waiting tasks at the appropriate
 * moment.
 *
 * This is implemented using struct set_affinity_pending. The first
 * __set_cpus_allowed_ptr() caller within a given Migrate-Disable region will
 * setup an instance of that struct and install it on the targeted task_struct.
 * Any and all further callers will reuse that instance. Those then wait for
 * a completion signaled at the tail of the CPU stopper callback (1), triggered
 * on the end of the Migrate-Disable region (i.e. outermost migrate_enable()).
 *
 *
 * (1) In the cases covered above. There is one more where the completion is
 * signaled within affine_move_task() itself: when a subsequent affinity request
 * occurs after the stopper bailed out due to the targeted task still being
 * Migrate-Disable. Consider:
 *
 *     Initial conditions: P0->cpus_mask = [0, 1]
 *
 *     CPU0       P1                P2
 *     <P0>
 *       migrate_disable();
 *       <preempted>
 *                        set_cpus_allowed_ptr(P0, [1]);
 *                          <blocks>
 *     <migration/0>
 *       migration_cpu_stop()
 *         is_migration_disabled()
 *           <bails>
 *                                                       set_cpus_allowed_ptr(P0, [0, 1]);
 *                                                         <signal completion>
 *                          <awakes>
 *
 * Note that the above is safe vs a concurrent migrate_enable(), as any
 * pending affinity completion is preceded by an uninstallation of
 * p->migration_pending done with p->pi_lock held.
 */
static int affine_move_task(struct rq *rq,
                            struct task_struct *p,
                            struct rq_flags *rf,
                            int dest_cpu, unsigned int flags)
{
    struct set_affinity_pending my_pending = { }, *pending = NULL;
    bool stop_pending, complete = false;

    /* Can the task run on the task's current CPU? If so, we're done */
    if (cpumask_test_cpu(task_cpu(p), &p->cpus_mask)) {
        struct task_struct *push_task = NULL;

        if ((flags & SCA_MIGRATE_ENABLE) &&
            (p->migration_flags & MDF_PUSH) && !rq->push_busy) {
            rq->push_busy = true;
            push_task = get_task_struct(p);
        }

        /*
         * If there are pending waiters, but no pending stop_work,
         * then complete now.
         */
        pending = p->migration_pending;
        if (pending && !pending->stop_pending) {
            p->migration_pending = NULL;
            complete = true;
        }

        task_rq_unlock(rq, p, rf);

        if (push_task) {
            stop_one_cpu_nowait(rq->cpu, push_cpu_stop,
                                p, &rq->push_work);
        }

        if (complete)
            complete_all(&pending->done);

        return 0;
    }
    panic("%s: NOT-implemented!\n", __func__);
}

/*
 * Called with both p->pi_lock and rq->lock held; drops both before returning.
 */
static int __set_cpus_allowed_ptr_locked(struct task_struct *p,
                                         const struct cpumask *new_mask,
                                         u32 flags,
                                         struct rq *rq,
                                         struct rq_flags *rf)
    __releases(rq->lock)
    __releases(p->pi_lock)
{
    const struct cpumask *cpu_allowed_mask = task_cpu_possible_mask(p);
    const struct cpumask *cpu_valid_mask = cpu_active_mask;
    bool kthread = p->flags & PF_KTHREAD;
    struct cpumask *user_mask = NULL;
    unsigned int dest_cpu;
    int ret = 0;

    update_rq_clock(rq);

    if (kthread || is_migration_disabled(p)) {
        /*
         * Kernel threads are allowed on online && !active CPUs,
         * however, during cpu-hot-unplug, even these might get pushed
         * away if not KTHREAD_IS_PER_CPU.
         *
         * Specifically, migration_disabled() tasks must not fail the
         * cpumask_any_and_distribute() pick below, esp. so on
         * SCA_MIGRATE_ENABLE, otherwise we'll not call
         * set_cpus_allowed_common() and actually reset p->cpus_ptr.
         */
        cpu_valid_mask = cpu_online_mask;
    }

    if (!kthread && !cpumask_subset(new_mask, cpu_allowed_mask)) {
        ret = -EINVAL;
        goto out;
    }

    /*
     * Must re-check here, to close a race against __kthread_bind(),
     * sched_setaffinity() is not guaranteed to observe the flag.
     */
    if ((flags & SCA_CHECK) && (p->flags & PF_NO_SETAFFINITY)) {
        ret = -EINVAL;
        goto out;
    }

    if (!(flags & SCA_MIGRATE_ENABLE)) {
        if (cpumask_equal(&p->cpus_mask, new_mask))
            goto out;

        if (WARN_ON_ONCE(p == current && is_migration_disabled(p) &&
                         !cpumask_test_cpu(task_cpu(p), new_mask))) {
            ret = -EBUSY;
            goto out;
        }
    }

    /*
     * Picking a ~random cpu helps in cases where we are changing affinity
     * for groups of tasks (ie. cpuset), so that load balancing is not
     * immediately required to distribute the tasks within their new mask.
     */
    dest_cpu = cpumask_any_and_distribute(cpu_valid_mask, new_mask);
    if (dest_cpu >= nr_cpu_ids) {
        ret = -EINVAL;
        goto out;
    }

    __do_set_cpus_allowed(p, new_mask, flags);

    if (flags & SCA_USER)
        user_mask = clear_user_cpus_ptr(p);

    ret = affine_move_task(rq, p, rf, dest_cpu, flags);

    kfree(user_mask);

    return ret;

 out:
    task_rq_unlock(rq, p, rf);

    return ret;
}

/*
 * Change a given task's CPU affinity. Migrate the thread to a
 * proper CPU and schedule it away if the CPU it's executing on
 * is removed from the allowed bitmask.
 *
 * NOTE: the caller must have a valid reference to the task, the
 * task must not exit() & deallocate itself prematurely. The
 * call is not atomic; no spinlocks may be held.
 */
static int __set_cpus_allowed_ptr(struct task_struct *p,
                                  const struct cpumask *new_mask, u32 flags)
{
    struct rq_flags rf;
    struct rq *rq;

    rq = task_rq_lock(p, &rf);
    return __set_cpus_allowed_ptr_locked(p, new_mask, flags, rq, &rf);
}

int set_cpus_allowed_ptr(struct task_struct *p, const struct cpumask *new_mask)
{
    return __set_cpus_allowed_ptr(p, new_mask, 0);
}
EXPORT_SYMBOL_GPL(set_cpus_allowed_ptr);

/*
 * task_rq_lock - lock p->pi_lock and lock the rq @p resides on.
 */
struct rq *task_rq_lock(struct task_struct *p, struct rq_flags *rf)
    __acquires(p->pi_lock)
    __acquires(rq->lock)
{
    struct rq *rq;

    for (;;) {
        raw_spin_lock_irqsave(&p->pi_lock, rf->flags);
        rq = task_rq(p);
        raw_spin_rq_lock(rq);
        /*
         *  move_queued_task()      task_rq_lock()
         *
         *  ACQUIRE (rq->lock)
         *  [S] ->on_rq = MIGRATING     [L] rq = task_rq()
         *  WMB (__set_task_cpu())      ACQUIRE (rq->lock);
         *  [S] ->cpu = new_cpu     [L] task_rq()
         *                  [L] ->on_rq
         *  RELEASE (rq->lock)
         *
         * If we observe the old CPU in task_rq_lock(), the acquire of
         * the old rq->lock will fully serialize against the stores.
         *
         * If we observe the new CPU in task_rq_lock(), the address
         * dependency headed by '[L] rq = task_rq()' and the acquire
         * will pair with the WMB to ensure we then also see migrating.
         */
        if (likely(rq == task_rq(p) && !task_on_rq_migrating(p))) {
            rq_pin_lock(rq, rf);
            return rq;
        }
        raw_spin_rq_unlock(rq);
        raw_spin_unlock_irqrestore(&p->pi_lock, rf->flags);

        while (unlikely(task_on_rq_migrating(p)))
            cpu_relax();
    }
}

bool cpus_share_cache(int this_cpu, int that_cpu)
{
    if (this_cpu == that_cpu)
        return true;

    //return per_cpu(sd_llc_id, this_cpu) == per_cpu(sd_llc_id, that_cpu);
    panic("%s: NO implementation!\n", __func__);
}

/*
 * migration_cpu_stop - this will be executed by a highprio stopper thread
 * and performs thread migration by bumping thread off CPU then
 * 'pushing' onto another runqueue.
 */
static int migration_cpu_stop(void *data)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * sched_exec - execve() is a valuable balancing opportunity, because at
 * this point the task has the smallest effective memory and cache footprint.
 */
void sched_exec(void)
{
    struct task_struct *p = current;
    unsigned long flags;
    int dest_cpu;

    raw_spin_lock_irqsave(&p->pi_lock, flags);
    dest_cpu = p->sched_class->select_task_rq(p, task_cpu(p), WF_EXEC);
    if (dest_cpu == smp_processor_id())
        goto unlock;

    if (likely(cpu_active(dest_cpu))) {
        struct migration_arg arg = { p, dest_cpu };

        raw_spin_unlock_irqrestore(&p->pi_lock, flags);
        stop_one_cpu(task_cpu(p), migration_cpu_stop, &arg);
        return;
    }
unlock:
    raw_spin_unlock_irqrestore(&p->pi_lock, flags);
}

int wake_up_state(struct task_struct *p, unsigned int state)
{
    return try_to_wake_up(p, state, 0);
}

void sched_set_stop_task(int cpu, struct task_struct *stop)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * In the semi idle case, use the nearest busy CPU for migrating timers
 * from an idle CPU.  This is good for power-savings.
 *
 * We don't do similar optimization for completely idle system, as
 * selecting an idle CPU will add more delays to the timers than intended
 * (as that CPU's timer base may not be uptodate wrt jiffies etc).
 */
int get_nohz_timer_target(void)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * sched_class::set_cpus_allowed must do the below, but is not required to
 * actually call this function.
 */
void set_cpus_allowed_common(struct task_struct *p,
                             const struct cpumask *new_mask, u32 flags)
{
    if (flags & (SCA_MIGRATE_ENABLE | SCA_MIGRATE_DISABLE)) {
        p->cpus_ptr = new_mask;
        return;
    }

    cpumask_copy(&p->cpus_mask, new_mask);
    p->nr_cpus_allowed = cpumask_weight(new_mask);
}

static int __sched_setscheduler(struct task_struct *p,
                                const struct sched_attr *attr,
                                bool user, bool pi)
{
    int oldpolicy = -1, policy = attr->sched_policy;
    int retval, oldprio, newprio, queued, running;
    const struct sched_class *prev_class;
    struct callback_head *head;
    struct rq_flags rf;
    int reset_on_fork;
    int queue_flags = DEQUEUE_SAVE | DEQUEUE_MOVE | DEQUEUE_NOCLOCK;
    struct rq *rq;

    /* The pi code expects interrupts enabled */
    BUG_ON(pi && in_interrupt());

 recheck:
    /* Double check policy once rq lock held: */
    if (policy < 0) {
        reset_on_fork = p->sched_reset_on_fork;
        policy = oldpolicy = p->policy;
    } else {
        reset_on_fork = !!(attr->sched_flags & SCHED_FLAG_RESET_ON_FORK);

        if (!valid_policy(policy))
            return -EINVAL;
    }

    if (attr->sched_flags & ~(SCHED_FLAG_ALL | SCHED_FLAG_SUGOV))
        return -EINVAL;

    /*
     * Valid priorities for SCHED_FIFO and SCHED_RR are
     * 1..MAX_RT_PRIO-1, valid priority for SCHED_NORMAL,
     * SCHED_BATCH and SCHED_IDLE is 0.
     */
    if (attr->sched_priority > MAX_RT_PRIO-1)
        return -EINVAL;
    if ((dl_policy(policy) && !__checkparam_dl(attr)) ||
        (rt_policy(policy) != (attr->sched_priority != 0)))
        return -EINVAL;

#if 0
    /*
     * Allow unprivileged RT tasks to decrease priority:
     */
    if (user && !capable(CAP_SYS_NICE)) {
        panic("%s: 1!\n", __func__);
    }
#endif

    if (user) {
        if (attr->sched_flags & SCHED_FLAG_SUGOV)
            return -EINVAL;
    }

    /* Update task specific "requested" clamps */
    if (attr->sched_flags & SCHED_FLAG_UTIL_CLAMP) {
        retval = uclamp_validate(p, attr);
        if (retval)
            return retval;
    }

    if (pi)
        cpuset_read_lock();

    /*
     * Make sure no PI-waiters arrive (or leave) while we are
     * changing the priority of the task:
     *
     * To be able to change p->policy safely, the appropriate
     * runqueue lock must be held.
     */
    rq = task_rq_lock(p, &rf);
    update_rq_clock(rq);

    /*
     * Changing the policy of the stop threads its a very bad idea:
     */
    if (p == rq->stop) {
        retval = -EINVAL;
        goto unlock;
    }

    /*
     * If not changing anything there's no need to proceed further,
     * but store a possible modification of reset_on_fork.
     */
    if (unlikely(policy == p->policy)) {
        if (fair_policy(policy) && attr->sched_nice != task_nice(p))
            goto change;
        if (rt_policy(policy) && attr->sched_priority != p->rt_priority)
            goto change;
        if (dl_policy(policy) && dl_param_changed(p, attr))
            goto change;
        if (attr->sched_flags & SCHED_FLAG_UTIL_CLAMP)
            goto change;

        p->sched_reset_on_fork = reset_on_fork;
        retval = 0;
        goto unlock;
    }

 change:

    panic("%s: END!\n", __func__);
    return 0;

 unlock:
    task_rq_unlock(rq, p, &rf);
    if (pi)
        cpuset_read_unlock();
    return retval;
}

static int _sched_setscheduler(struct task_struct *p, int policy,
                               const struct sched_param *param, bool check)
{
    struct sched_attr attr = {
        .sched_policy   = policy,
        .sched_priority = param->sched_priority,
        .sched_nice = PRIO_TO_NICE(p->static_prio),
    };

    /* Fixup the legacy SCHED_RESET_ON_FORK hack. */
    if ((policy != SETPARAM_POLICY) && (policy & SCHED_RESET_ON_FORK)) {
        attr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
        policy &= ~SCHED_RESET_ON_FORK;
        attr.sched_policy = policy;
    }

    return __sched_setscheduler(p, &attr, check, true);
}

/**
 * sched_setscheduler_nocheck - change the scheduling policy and/or RT priority of a thread from kernelspace.
 * @p: the task in question.
 * @policy: new policy.
 * @param: structure containing the new RT priority.
 *
 * Just like sched_setscheduler, only don't bother checking if the
 * current context has permission.  For example, this is needed in
 * stop_machine(): we create temporary high priority worker threads,
 * but our caller might not have that capability.
 *
 * Return: 0 on success. An error code otherwise.
 */
int sched_setscheduler_nocheck(struct task_struct *p, int policy,
                               const struct sched_param *param)
{
    return _sched_setscheduler(p, policy, param, false);
}

void __init sched_init_smp(void)
{
    /*
     * There's no userspace yet to cause hotplug operations; hence all the
     * CPU masks are stable and all blatant races in the below code cannot
     * happen.
     */
    mutex_lock(&sched_domains_mutex);
    sched_init_domains(cpu_active_mask);
    mutex_unlock(&sched_domains_mutex);

    /* Move init over to a non-isolated CPU */
    if (set_cpus_allowed_ptr(current,
                             housekeeping_cpumask(HK_TYPE_DOMAIN)) < 0)
        BUG();

    current->flags &= ~PF_NO_SETAFFINITY;
    sched_init_granularity();

    init_sched_rt_class();
    init_sched_dl_class();

    sched_smp_initialized = true;
}
