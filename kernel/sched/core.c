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
#if 0
#include <linux/sched/clock.h>
#include <linux/sched/cond_resched.h>
#include <linux/sched/isolation.h>
#include <linux/sched/nohz.h>
#include <linux/sched/rseq_api.h>
#endif
#include <linux/sched/debug.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/mm.h>
#include <linux/sched/rt.h>

#include <linux/init_task.h>
#include <linux/mmzone.h>
#include <linux/blkdev.h>
#include <linux/kthread.h>
#if 0
#include <linux/context_tracking.h>
#include <linux/cpuset.h>
#include <linux/delayacct.h>
#include <linux/interrupt.h>
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

#include <asm/switch_to.h>
#if 0
#include <uapi/linux/sched/types.h>

#include <asm/tlb.h>
#endif

#include "sched.h"
#if 0
#include "stats.h"
#include "autogroup.h"

#include "pelt.h"
#include "smp.h"

#include "../workqueue_internal.h"
#include "../../fs/io-wq.h"
#endif
#include "../smpboot.h"

__read_mostly int scheduler_running;

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

static inline void sched_submit_work(struct task_struct *tsk)
{
    panic("%s: NO implementation!\n", __func__);
}

static void sched_update_worker(struct task_struct *tsk)
{
#if 0
    if (tsk->flags & (PF_WQ_WORKER | PF_IO_WORKER)) {
        if (tsk->flags & PF_WQ_WORKER)
            wq_worker_running(tsk);
        else
            io_wq_worker_running(tsk);
    }
#endif
    panic("%s: NO implementation!\n", __func__);
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

static void put_prev_task_balance(struct rq *rq, struct task_struct *prev,
                                  struct rq_flags *rf)
{
#if 0
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
#endif

    put_prev_task(rq, prev);
}

/*
 * Pick up the highest-prio task:
 */
static inline struct task_struct *
__pick_next_task(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
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
pick_next_task(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
    return __pick_next_task(rq, prev, rf);
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
#if 0
    rseq_preempt(prev);
    fire_sched_out_preempt_notifiers(prev, next);
    kmap_local_sched_out();
#endif
    prepare_task(next);
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

#if 0
    rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);
#endif

    /* Here we just switch the register state and the stack. */
    switch_to(prev, next, prev);
    barrier();

    panic("%s: mm(%p) END!\n", __func__, next->mm);
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

    printk("%s: rq(%p) prev(%p)\n", __func__, rq, prev);
    next = pick_next_task(rq, prev, &rf);

    clear_tsk_need_resched(prev);

    if (likely(prev != next)) {
        rq->nr_switches++;
        /*
         * RCU users of rcu_dereference(rq->curr) may not see
         * changes to task_struct made by pick_next_task().
         */
        RCU_INIT_POINTER(rq->curr, next);
#if 0
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
#endif

        /* Also unlocks the rq: */
        rq = context_switch(rq, prev, next, &rf);
    } else {
        panic("%s: prev(%p) next(%p)\n", __func__, prev, next);
    }
    panic("%s: END!\n", __func__);
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
    panic("%s: NO implementation!\n", __func__);
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
    p->on_rq = 0;

    p->se.on_rq = 0;
    p->se.vruntime = 0;
    INIT_LIST_HEAD(&p->se.group_node);

    p->se.cfs_rq = NULL;
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

    if (dl_prio(p->prio))
        return -EAGAIN;
    else if (rt_prio(p->prio))
        p->sched_class = &rt_sched_class;
    else
        p->sched_class = &fair_sched_class;

#if 0
    init_entity_runnable_average(&p->se);
#endif

    p->on_cpu = 0;

    init_task_preempt_count(p);

#if 0
    plist_node_init(&p->pushable_tasks, MAX_PRIO);
    RB_CLEAR_NODE(&p->pushable_dl_tasks);
#endif

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

static inline void enqueue_task(struct rq *rq, struct task_struct *p, int flags)
{
#if 0
    if (!(flags & ENQUEUE_NOCLOCK))
        update_rq_clock(rq);

    if (!(flags & ENQUEUE_RESTORE)) {
        sched_info_enqueue(rq, p);
    }
#endif

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
#if 0
    update_rq_clock(rq);
    post_init_entity_util_avg(p);
#endif

    activate_task(rq, p, ENQUEUE_NOCLOCK);
#if 0
    check_preempt_curr(rq, p, WF_FORK);
#endif
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
}

static void nohz_csd_func(void *info)
{
    panic("%s: NO implementation!", __func__);
}

static void hrtick_rq_init(struct rq *rq)
{
#if 0
    INIT_CSD(&rq->hrtick_csd, __hrtick_start, rq);
    hrtimer_init(&rq->hrtick_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_HARD);
    rq->hrtick_timer.function = hrtick;
#endif
    pr_warn("!!!!!! %s: NO implementation!", __func__);
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
try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
{
    panic("%s: NOT-implemented!\n", __func__);
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
