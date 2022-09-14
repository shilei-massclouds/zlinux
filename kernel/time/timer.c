// SPDX-License-Identifier: GPL-2.0

//#include <linux/kernel_stat.h>
#include <linux/export.h>
//#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#if 0
#include <linux/swap.h>
#include <linux/pid_namespace.h>
#include <linux/notifier.h>
#endif
#include <linux/thread_info.h>
#include <linux/jiffies.h>
#if 0
#include <linux/time.h>
#endif
#include <linux/timer.h>
#include <linux/posix-timers.h>
#include <linux/cpu.h>
#if 0
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/tick.h>
#include <linux/kallsyms.h>
#include <linux/sched/signal.h>
#include <linux/sched/sysctl.h>
#include <linux/random.h>
#endif
#include <linux/irq_work.h>
#include <linux/sched/nohz.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/sched/debug.h>

#include <linux/uaccess.h>
//#include <asm/unistd.h>
#include <asm/div64.h>
//#include <asm/timex.h>
//#include <asm/io.h>

#include "tick-internal.h"

__visible u64 jiffies_64 __cacheline_aligned_in_smp = INITIAL_JIFFIES;

EXPORT_SYMBOL(jiffies_64);

unsigned int sysctl_timer_migration = 1;

DEFINE_STATIC_KEY_FALSE(timers_migration_enabled);

static void timers_update_migration(void)
{
    if (sysctl_timer_migration && tick_nohz_active)
        static_branch_enable(&timers_migration_enabled);
    else
        static_branch_disable(&timers_migration_enabled);
}

/* Clock divisor for the next level */
#define LVL_CLK_SHIFT   3
#define LVL_CLK_DIV (1UL << LVL_CLK_SHIFT)
#define LVL_CLK_MASK    (LVL_CLK_DIV - 1)
#define LVL_SHIFT(n)    ((n) * LVL_CLK_SHIFT)
#define LVL_GRAN(n) (1UL << LVL_SHIFT(n))

/*
 * The time start value for each level to select the bucket at enqueue
 * time. We start from the last possible delta of the previous level
 * so that we can later add an extra LVL_GRAN(n) to n (see calc_index()).
 */
#define LVL_START(n)    ((LVL_SIZE - 1) << (((n) - 1) * LVL_CLK_SHIFT))

/* Size of each clock level */
#define LVL_BITS    6
#define LVL_SIZE    (1UL << LVL_BITS)
#define LVL_MASK    (LVL_SIZE - 1)
#define LVL_OFFS(n) ((n) * LVL_SIZE)

/* Level depth */
#if HZ > 100
# define LVL_DEPTH  9
# else
# define LVL_DEPTH  8
#endif

/* The cutoff (max. capacity of the wheel) */
#define WHEEL_TIMEOUT_CUTOFF (LVL_START(LVL_DEPTH))
#define WHEEL_TIMEOUT_MAX \
    (WHEEL_TIMEOUT_CUTOFF - LVL_GRAN(LVL_DEPTH - 1))

/*
 * The resulting wheel size. If NOHZ is configured we allocate two
 * wheels so we have a separate storage for the deferrable timers.
 */
#define WHEEL_SIZE  (LVL_SIZE * LVL_DEPTH)

#define NR_BASES   2
#define BASE_STD   0
#define BASE_DEF   1

struct timer_base {
    raw_spinlock_t      lock;
    struct timer_list   *running_timer;
    unsigned long       clk;
    unsigned long       next_expiry;
    unsigned int        cpu;
    bool                next_expiry_recalc;
    bool                is_idle;
    bool                timers_pending;
    DECLARE_BITMAP(pending_map, WHEEL_SIZE);
    struct hlist_head   vectors[WHEEL_SIZE];
} ____cacheline_aligned;

/*
 * Since schedule_timeout()'s timer is defined on the stack, it must store
 * the target task on the stack as well.
 */
struct process_timer {
    struct timer_list timer;
    struct task_struct *task;
};

static void process_timeout(struct timer_list *t)
{
    struct process_timer *timeout = from_timer(timeout, t, timer);

    wake_up_process(timeout->task);
}

static DEFINE_PER_CPU(struct timer_base, timer_bases[NR_BASES]);

#define MOD_TIMER_PENDING_ONLY      0x01
#define MOD_TIMER_REDUCE            0x02
#define MOD_TIMER_NOTPENDING        0x04

static inline void timer_base_init_expiry_lock(struct timer_base *base) { }
static inline void timer_base_lock_expiry(struct timer_base *base) { }
static inline void timer_base_unlock_expiry(struct timer_base *base) { }
static inline void timer_sync_wait_running(struct timer_base *base) { }
static inline void del_timer_wait_running(struct timer_list *timer) { }

static inline struct timer_base *get_timer_this_cpu_base(u32 tflags)
{
    struct timer_base *base = this_cpu_ptr(&timer_bases[BASE_STD]);

    /*
     * If the timer is deferrable and NO_HZ_COMMON is set then we need
     * to use the deferrable base.
     */
    if (tflags & TIMER_DEFERRABLE)
        base = this_cpu_ptr(&timer_bases[BASE_DEF]);
    return base;
}

static inline struct timer_base *get_timer_cpu_base(u32 tflags, u32 cpu)
{
    struct timer_base *base = per_cpu_ptr(&timer_bases[BASE_STD], cpu);

    /*
     * If the timer is deferrable and NO_HZ_COMMON is set then we need
     * to use the deferrable base.
     */
    if ((tflags & TIMER_DEFERRABLE))
        base = per_cpu_ptr(&timer_bases[BASE_DEF], cpu);
    return base;
}

static inline struct timer_base *get_timer_base(u32 tflags)
{
    return get_timer_cpu_base(tflags, tflags & TIMER_CPUMASK);
}

/*
 * We are using hashed locking: Holding per_cpu(timer_bases[x]).lock means
 * that all timers which are tied to this base are locked, and the base itself
 * is locked too.
 *
 * So __run_timers/migrate_timers can safely modify all timers which could
 * be found in the base->vectors array.
 *
 * When a timer is migrating then the TIMER_MIGRATING flag is set and we need
 * to wait until the migration is done.
 */
static struct timer_base *
lock_timer_base(struct timer_list *timer, unsigned long *flags)
    __acquires(timer->base->lock)
{
    for (;;) {
        struct timer_base *base;
        u32 tf;

        /*
         * We need to use READ_ONCE() here, otherwise the compiler
         * might re-read @tf between the check for TIMER_MIGRATING
         * and spin_lock().
         */
        tf = READ_ONCE(timer->flags);

        if (!(tf & TIMER_MIGRATING)) {
            base = get_timer_base(tf);
            raw_spin_lock_irqsave(&base->lock, *flags);
            if (timer->flags == tf)
                return base;
            raw_spin_unlock_irqrestore(&base->lock, *flags);
        }
        cpu_relax();
    }
}

static inline void forward_timer_base(struct timer_base *base)
{
    unsigned long jnow = READ_ONCE(jiffies);

    /*
     * No need to forward if we are close enough below jiffies.
     * Also while executing timers, base->clk is 1 offset ahead
     * of jiffies to avoid endless requeuing to current jiffies.
     */
    if ((long)(jnow - base->clk) < 1)
        return;

    /*
     * If the next expiry value is > jiffies, then we fast forward to
     * jiffies otherwise we forward to the next expiry value.
     */
    if (time_after(base->next_expiry, jnow)) {
        base->clk = jnow;
    } else {
        if (WARN_ON_ONCE(time_before(base->next_expiry, base->clk)))
            return;
        base->clk = base->next_expiry;
    }
}

static inline unsigned int timer_get_idx(struct timer_list *timer)
{
    return (timer->flags & TIMER_ARRAYMASK) >> TIMER_ARRAYSHIFT;
}

static inline
void detach_timer(struct timer_list *timer, bool clear_pending)
{
    struct hlist_node *entry = &timer->entry;

    __hlist_del(entry);
    if (clear_pending)
        entry->pprev = NULL;
    entry->next = LIST_POISON2;
}

static int detach_if_pending(struct timer_list *timer,
                             struct timer_base *base,
                             bool clear_pending)
{
    unsigned idx = timer_get_idx(timer);

    if (!timer_pending(timer))
        return 0;

    if (hlist_is_singular_node(&timer->entry, base->vectors + idx)) {
        __clear_bit(idx, base->pending_map);
        base->next_expiry_recalc = true;
    }

    detach_timer(timer, clear_pending);
    return 1;
}

static inline struct timer_base *
get_target_base(struct timer_base *base, unsigned tflags)
{
    if (static_branch_likely(&timers_migration_enabled) &&
        !(tflags & TIMER_PINNED))
        return get_timer_cpu_base(tflags, get_nohz_timer_target());
    return get_timer_this_cpu_base(tflags);
}

/*
 * Helper function to calculate the array index for a given expiry
 * time.
 */
static inline unsigned calc_index(unsigned long expires, unsigned lvl,
                                  unsigned long *bucket_expiry)
{

    /*
     * The timer wheel has to guarantee that a timer does not fire
     * early. Early expiry can happen due to:
     * - Timer is armed at the edge of a tick
     * - Truncation of the expiry time in the outer wheel levels
     *
     * Round up with level granularity to prevent this.
     */
    expires = (expires + LVL_GRAN(lvl)) >> LVL_SHIFT(lvl);
    *bucket_expiry = expires << LVL_SHIFT(lvl);
    return LVL_OFFS(lvl) + (expires & LVL_MASK);
}

static int calc_wheel_index(unsigned long expires, unsigned long clk,
                            unsigned long *bucket_expiry)
{
    unsigned long delta = expires - clk;
    unsigned int idx;

    if (delta < LVL_START(1)) {
        idx = calc_index(expires, 0, bucket_expiry);
    } else if (delta < LVL_START(2)) {
        idx = calc_index(expires, 1, bucket_expiry);
    } else if (delta < LVL_START(3)) {
        idx = calc_index(expires, 2, bucket_expiry);
    } else if (delta < LVL_START(4)) {
        idx = calc_index(expires, 3, bucket_expiry);
    } else if (delta < LVL_START(5)) {
        idx = calc_index(expires, 4, bucket_expiry);
    } else if (delta < LVL_START(6)) {
        idx = calc_index(expires, 5, bucket_expiry);
    } else if (delta < LVL_START(7)) {
        idx = calc_index(expires, 6, bucket_expiry);
    } else if (LVL_DEPTH > 8 && delta < LVL_START(8)) {
        idx = calc_index(expires, 7, bucket_expiry);
    } else if ((long) delta < 0) {
        idx = clk & LVL_MASK;
        *bucket_expiry = clk;
    } else {
        /*
         * Force expire obscene large timeouts to expire at the
         * capacity limit of the wheel.
         */
        if (delta >= WHEEL_TIMEOUT_CUTOFF)
            expires = clk + WHEEL_TIMEOUT_MAX;

        idx = calc_index(expires, LVL_DEPTH - 1, bucket_expiry);
    }
    return idx;
}
    
static inline
void timer_set_idx(struct timer_list *timer, unsigned int idx)
{
    timer->flags = (timer->flags & ~TIMER_ARRAYMASK) |
        idx << TIMER_ARRAYSHIFT;
}

/*
 * Enqueue the timer into the hash bucket, mark it pending in
 * the bitmap, store the index in the timer flags then wake up
 * the target CPU if needed.
 */
static void enqueue_timer(struct timer_base *base,
                          struct timer_list *timer,
                          unsigned int idx,
                          unsigned long bucket_expiry)
{
    hlist_add_head(&timer->entry, base->vectors + idx);
    __set_bit(idx, base->pending_map);
    timer_set_idx(timer, idx);

    /*
     * Check whether this is the new first expiring timer. The
     * effective expiry time of the timer is required here
     * (bucket_expiry) instead of timer->expires.
     */
    if (time_before(bucket_expiry, base->next_expiry)) {
        panic("%s: 1!\n", __func__);
    }
}

static void internal_add_timer(struct timer_base *base,
                               struct timer_list *timer)
{
    unsigned long bucket_expiry;
    unsigned int idx;

    idx = calc_wheel_index(timer->expires, base->clk, &bucket_expiry);
    enqueue_timer(base, timer, idx, bucket_expiry);
}

static inline int
__mod_timer(struct timer_list *timer, unsigned long expires,
            unsigned int options)
{
    unsigned long clk = 0, flags, bucket_expiry;
    struct timer_base *base, *new_base;
    unsigned int idx = UINT_MAX;
    int ret = 0;

    BUG_ON(!timer->function);

    /*
     * This is a common optimization triggered by the networking code - if
     * the timer is re-modified to have the same timeout or ends up in the
     * same array bucket then just return:
     */
    if (!(options & MOD_TIMER_NOTPENDING) && timer_pending(timer)) {
        panic("%s: 1!\n", __func__);
    } else {
        base = lock_timer_base(timer, &flags);
        forward_timer_base(base);
    }

    ret = detach_if_pending(timer, base, false);
    if (!ret && (options & MOD_TIMER_PENDING_ONLY))
        goto out_unlock;

    new_base = get_target_base(base, timer->flags);

    if (base != new_base) {
        panic("%s: 2!\n", __func__);
    }

    timer->expires = expires;
    /*
     * If 'idx' was calculated above and the base time did not advance
     * between calculating 'idx' and possibly switching the base, only
     * enqueue_timer() is required. Otherwise we need to (re)calculate
     * the wheel index via internal_add_timer().
     */
    if (idx != UINT_MAX && clk == base->clk)
        enqueue_timer(base, timer, idx, bucket_expiry);
    else
        internal_add_timer(base, timer);

 out_unlock:
    raw_spin_unlock_irqrestore(&base->lock, flags);

    return ret;
}

/**
 * schedule_timeout - sleep until timeout
 * @timeout: timeout value in jiffies
 *
 * Make the current task sleep until @timeout jiffies have elapsed.
 * The function behavior depends on the current task state
 * (see also set_current_state() description):
 *
 * %TASK_RUNNING - the scheduler is called, but the task does not sleep
 * at all. That happens because sched_submit_work() does nothing for
 * tasks in %TASK_RUNNING state.
 *
 * %TASK_UNINTERRUPTIBLE - at least @timeout jiffies are guaranteed to
 * pass before the routine returns unless the current task is explicitly
 * woken up, (e.g. by wake_up_process()).
 *
 * %TASK_INTERRUPTIBLE - the routine may return early if a signal is
 * delivered to the current task or the current task is explicitly woken
 * up.
 *
 * The current task state is guaranteed to be %TASK_RUNNING when this
 * routine returns.
 *
 * Specifying a @timeout value of %MAX_SCHEDULE_TIMEOUT will schedule
 * the CPU away without a bound on the timeout. In this case the return
 * value will be %MAX_SCHEDULE_TIMEOUT.
 *
 * Returns 0 when the timer has expired otherwise the remaining time in
 * jiffies will be returned. In all cases the return value is guaranteed
 * to be non-negative.
 */
signed long __sched schedule_timeout(signed long timeout)
{
    struct process_timer timer;
    unsigned long expire;

    switch (timeout)
    {
    case MAX_SCHEDULE_TIMEOUT:
        /*
         * These two special cases are useful to be comfortable
         * in the caller. Nothing more. We could take
         * MAX_SCHEDULE_TIMEOUT from one of the negative value
         * but I' d like to return a valid offset (>=0) to allow
         * the caller to do everything it want with the retval.
         */
        schedule();
        goto out;
    default:
        /*
         * Another bit of PARANOID. Note that the retval will be
         * 0 since no piece of kernel is supposed to do a check
         * for a negative retval of schedule_timeout() (since it
         * should never happens anyway). You just have the printk()
         * that will tell you if something is gone wrong and where.
         */
        if (timeout < 0) {
            printk(KERN_ERR "schedule_timeout: wrong timeout "
                   "value %lx\n", timeout);
            //dump_stack();
            __set_current_state(TASK_RUNNING);
            goto out;
        }
    }

    expire = timeout + jiffies;

    timer.task = current;
    timer_setup_on_stack(&timer.timer, process_timeout, 0);
    __mod_timer(&timer.timer, expire, MOD_TIMER_NOTPENDING);
    schedule();
    del_singleshot_timer_sync(&timer.timer);

    /* Remove the timer from the object tracker */
    destroy_timer_on_stack(&timer.timer);

    timeout = expire - jiffies;

    return 0;

 out:
    return timeout < 0 ? 0 : timeout;
}

signed long __sched schedule_timeout_uninterruptible(signed long timeout)
{
    panic("%s: NO implemented!\n", __func__);
#if 0
    __set_current_state(TASK_UNINTERRUPTIBLE);
    return schedule_timeout(timeout);
#endif
}
EXPORT_SYMBOL(schedule_timeout_uninterruptible);

static void do_init_timer(struct timer_list *timer,
                          void (*func)(struct timer_list *),
                          unsigned int flags,
                          const char *name,
                          struct lock_class_key *key)
{
    timer->entry.pprev = NULL;
    timer->function = func;
    if (WARN_ON_ONCE(flags & ~TIMER_INIT_FLAGS))
        flags &= TIMER_INIT_FLAGS;
    timer->flags = flags | raw_smp_processor_id();
}

/**
 * init_timer_key - initialize a timer
 * @timer: the timer to be initialized
 * @func: timer callback function
 * @flags: timer flags
 * @name: name of the timer
 * @key: lockdep class key of the fake lock used for tracking timer
 *       sync lock dependencies
 *
 * init_timer_key() must be done to a timer prior calling *any* of the
 * other timer functions.
 */
void init_timer_key(struct timer_list *timer,
                    void (*func)(struct timer_list *),
                    unsigned int flags,
                    const char *name,
                    struct lock_class_key *key)
{
    do_init_timer(timer, func, flags, name, key);
}
EXPORT_SYMBOL(init_timer_key);

/**
 * try_to_del_timer_sync - Try to deactivate a timer
 * @timer: timer to delete
 *
 * This function tries to deactivate a timer. Upon successful (ret >= 0)
 * exit the timer is not queued and the handler is not running on any CPU.
 */
int try_to_del_timer_sync(struct timer_list *timer)
{
    struct timer_base *base;
    unsigned long flags;
    int ret = -1;

    base = lock_timer_base(timer, &flags);

    if (base->running_timer != timer)
        ret = detach_if_pending(timer, base, true);

    raw_spin_unlock_irqrestore(&base->lock, flags);

    return ret;
}
EXPORT_SYMBOL(try_to_del_timer_sync);

/**
 * del_timer_sync - deactivate a timer and wait for the handler to finish.
 * @timer: the timer to be deactivated
 *
 * This function only differs from del_timer() on SMP: besides deactivating
 * the timer it also makes sure the handler has finished executing on other
 * CPUs.
 *
 * Synchronization rules: Callers must prevent restarting of the timer,
 * otherwise this function is meaningless. It must not be called from
 * interrupt contexts unless the timer is an irqsafe one. The caller must
 * not hold locks which would prevent completion of the timer's
 * handler. The timer's handler must not call add_timer_on(). Upon exit the
 * timer is not queued and the handler is not running on any CPU.
 *
 * Note: For !irqsafe timers, you must not hold locks that are held in
 *   interrupt context while calling this function. Even if the lock has
 *   nothing to do with the timer in question.  Here's why::
 *
 *    CPU0                             CPU1
 *    ----                             ----
 *                                     <SOFTIRQ>
 *                                       call_timer_fn();
 *                                       base->running_timer = mytimer;
 *    spin_lock_irq(somelock);
 *                                     <IRQ>
 *                                        spin_lock(somelock);
 *    del_timer_sync(mytimer);
 *    while (base->running_timer == mytimer);
 *
 * Now del_timer_sync() will never return and never release somelock.
 * The interrupt on the other CPU is waiting to grab somelock but
 * it has interrupted the softirq that CPU0 is waiting to finish.
 *
 * The function returns whether it has deactivated a pending timer or not.
 */
int del_timer_sync(struct timer_list *timer)
{
    int ret;

    /*
     * don't use it in hardirq context, because it
     * could lead to deadlock.
     */
    WARN_ON(in_irq() && !(timer->flags & TIMER_IRQSAFE));

    do {
        ret = try_to_del_timer_sync(timer);

        if (unlikely(ret < 0)) {
            del_timer_wait_running(timer);
            cpu_relax();
        }
    } while (ret < 0);

    return ret;
}
EXPORT_SYMBOL(del_timer_sync);

/**
 * del_timer - deactivate a timer.
 * @timer: the timer to be deactivated
 *
 * del_timer() deactivates a timer - this works on both active and inactive
 * timers.
 *
 * The function returns whether it has deactivated a pending timer or not.
 * (ie. del_timer() of an inactive timer returns 0, del_timer() of an
 * active timer returns 1.)
 */
int del_timer(struct timer_list *timer)
{
    struct timer_base *base;
    unsigned long flags;
    int ret = 0;

    if (timer_pending(timer)) {
        base = lock_timer_base(timer, &flags);
        ret = detach_if_pending(timer, base, true);
        raw_spin_unlock_irqrestore(&base->lock, flags);
    }

    return ret;
}
EXPORT_SYMBOL(del_timer);

/**
 * mod_timer - modify a timer's timeout
 * @timer: the timer to be modified
 * @expires: new timeout in jiffies
 *
 * mod_timer() is a more efficient way to update the expire field of an
 * active timer (if the timer is inactive it will be activated)
 *
 * mod_timer(timer, expires) is equivalent to:
 *
 *     del_timer(timer); timer->expires = expires; add_timer(timer);
 *
 * Note that if there are multiple unserialized concurrent users of the
 * same timer, then mod_timer() is the only safe way to modify the timeout,
 * since add_timer() cannot modify an already running timer.
 *
 * The function returns whether it has modified a pending timer or not.
 * (ie. mod_timer() of an inactive timer returns 0, mod_timer() of an
 * active timer returns 1.)
 */
int mod_timer(struct timer_list *timer, unsigned long expires)
{
    return __mod_timer(timer, expires, 0);
}
EXPORT_SYMBOL(mod_timer);

/*
 * We can use __set_current_state() here because schedule_timeout() calls
 * schedule() unconditionally.
 */
signed long __sched schedule_timeout_interruptible(signed long timeout)
{
    __set_current_state(TASK_INTERRUPTIBLE);
    return schedule_timeout(timeout);
}
EXPORT_SYMBOL(schedule_timeout_interruptible);
