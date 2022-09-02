// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 *  Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 *  Copyright(C) 2006-2007  Timesys Corp., Thomas Gleixner
 *
 *  High-resolution kernel timers
 *
 *  In contrast to the low-resolution timeout API, aka timer wheel,
 *  hrtimers provide finer resolution and accuracy depending on system
 *  configuration and capabilities.
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 *
 *  Credits:
 *  Based on the original timer wheel code
 *
 *  Help, testing, suggestions, bugfixes, improvements were
 *  provided by:
 *
 *  George Anzinger, Andrew Morton, Steven Rostedt, Roman Zippel
 *  et. al.
 */

#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/hrtimer.h>
//#include <linux/notifier.h>
#include <linux/syscalls.h>
#include <linux/interrupt.h>
#include <linux/tick.h>
#include <linux/err.h>
//#include <linux/debugobjects.h>
#include <linux/sched/signal.h>
//#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/sched/deadline.h>
#include <linux/sched/nohz.h>
#include <linux/sched/debug.h>
//#include <linux/timer.h>
//#include <linux/freezer.h>
#include <linux/compat.h>

#include <linux/uaccess.h>

#include "tick-internal.h"

unsigned int sysctl_timer_migration = 1;

DEFINE_STATIC_KEY_FALSE(timers_migration_enabled);

static inline void
hrtimer_cpu_base_init_expiry_lock(struct hrtimer_cpu_base *base) { }
static inline void
hrtimer_cpu_base_lock_expiry(struct hrtimer_cpu_base *base) { }
static inline void
hrtimer_cpu_base_unlock_expiry(struct hrtimer_cpu_base *base) { }
static inline
void hrtimer_sync_wait_running(struct hrtimer_cpu_base *base,
                               unsigned long flags)
{
}

/*
 * The timer bases:
 *
 * There are more clockids than hrtimer bases. Thus, we index
 * into the timer bases by the hrtimer_base_type enum. When trying
 * to reach a base using a clockid, hrtimer_clockid_to_base()
 * is used to convert from clockid to the proper hrtimer_base_type.
 */
DEFINE_PER_CPU(struct hrtimer_cpu_base, hrtimer_bases) =
{
    .lock = __RAW_SPIN_LOCK_UNLOCKED(hrtimer_bases.lock),
    .clock_base =
    {
        {
            .index = HRTIMER_BASE_MONOTONIC,
            .clockid = CLOCK_MONOTONIC,
            .get_time = &ktime_get,
        },
        {
            .index = HRTIMER_BASE_REALTIME,
            .clockid = CLOCK_REALTIME,
            .get_time = &ktime_get_real,
        },
        {
            .index = HRTIMER_BASE_BOOTTIME,
            .clockid = CLOCK_BOOTTIME,
            .get_time = &ktime_get_boottime,
        },
        {
            .index = HRTIMER_BASE_TAI,
            .clockid = CLOCK_TAI,
            .get_time = &ktime_get_clocktai,
        },
        {
            .index = HRTIMER_BASE_MONOTONIC_SOFT,
            .clockid = CLOCK_MONOTONIC,
            .get_time = &ktime_get,
        },
        {
            .index = HRTIMER_BASE_REALTIME_SOFT,
            .clockid = CLOCK_REALTIME,
            .get_time = &ktime_get_real,
        },
        {
            .index = HRTIMER_BASE_BOOTTIME_SOFT,
            .clockid = CLOCK_BOOTTIME,
            .get_time = &ktime_get_boottime,
        },
        {
            .index = HRTIMER_BASE_TAI_SOFT,
            .clockid = CLOCK_TAI,
            .get_time = &ktime_get_clocktai,
        },
    }
};

static const int hrtimer_clock_to_base_table[MAX_CLOCKS] = {
    /* Make sure we catch unsupported clockids */
    [0 ... MAX_CLOCKS - 1]  = HRTIMER_MAX_CLOCK_BASES,

    [CLOCK_REALTIME]    = HRTIMER_BASE_REALTIME,
    [CLOCK_MONOTONIC]   = HRTIMER_BASE_MONOTONIC,
    [CLOCK_BOOTTIME]    = HRTIMER_BASE_BOOTTIME,
    [CLOCK_TAI]         = HRTIMER_BASE_TAI,
};

/*
 * We require the migration_base for lock_hrtimer_base()/switch_hrtimer_base()
 * such that hrtimer_callback_running() can unconditionally dereference
 * timer->base->cpu_base
 */
static struct hrtimer_cpu_base migration_cpu_base = {
    .clock_base = { {
        .cpu_base = &migration_cpu_base,
        .seq      = SEQCNT_RAW_SPINLOCK_ZERO(migration_cpu_base.seq,
                                             &migration_cpu_base.lock),
    }, },
};

#define migration_base  migration_cpu_base.clock_base[0]

/*
 * Called from timekeeping code to reprogram the hrtimer interrupt device
 * on all cpus and to notify timerfd.
 */
void clock_was_set_delayed(void)
{
    //schedule_work(&hrtimer_work);
    panic("%s: END!\n", __func__);
}

static inline int hrtimer_clockid_to_base(clockid_t clock_id)
{
    if (likely(clock_id < MAX_CLOCKS)) {
        int base = hrtimer_clock_to_base_table[clock_id];

        if (likely(base != HRTIMER_MAX_CLOCK_BASES))
            return base;
    }
    WARN(1, "Invalid clockid %d. Using MONOTONIC\n", clock_id);
    return HRTIMER_BASE_MONOTONIC;
}

static void __hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
                           enum hrtimer_mode mode)
{
    bool softtimer = !!(mode & HRTIMER_MODE_SOFT);
    struct hrtimer_cpu_base *cpu_base;
    int base;

    memset(timer, 0, sizeof(struct hrtimer));

    cpu_base = raw_cpu_ptr(&hrtimer_bases);

    /*
     * POSIX magic: Relative CLOCK_REALTIME timers are not affected by
     * clock modifications, so they needs to become CLOCK_MONOTONIC to
     * ensure POSIX compliance.
     */
    if (clock_id == CLOCK_REALTIME && mode & HRTIMER_MODE_REL)
        clock_id = CLOCK_MONOTONIC;

    base = softtimer ? HRTIMER_MAX_CLOCK_BASES / 2 : 0;
    base += hrtimer_clockid_to_base(clock_id);
    timer->is_soft = softtimer;
    timer->is_hard = !!(mode & HRTIMER_MODE_HARD);
    timer->base = &cpu_base->clock_base[base];
    timerqueue_init(&timer->node);
}

/*
 * We are using hashed locking: holding per_cpu(hrtimer_bases)[n].lock
 * means that all timers which are tied to this base via timer->base are
 * locked, and the base itself is locked too.
 *
 * So __run_timers/migrate_timers can safely modify all timers which could
 * be found on the lists/queues.
 *
 * When the timer's base is locked, and the timer removed from list, it is
 * possible to set timer->base = &migration_base and drop the lock: the timer
 * remains locked.
 */
static
struct hrtimer_clock_base *
lock_hrtimer_base(const struct hrtimer *timer, unsigned long *flags)
{
    struct hrtimer_clock_base *base;

    for (;;) {
        base = READ_ONCE(timer->base);
        if (likely(base != &migration_base)) {
            pr_info("############### %s: 1 cpu_base(%lx)\n",
                    __func__, base->cpu_base);
            raw_spin_lock_irqsave(&base->cpu_base->lock, *flags);
            if (likely(base == timer->base))
                return base;
            /* The timer has migrated to another CPU: */
            raw_spin_unlock_irqrestore(&base->cpu_base->lock, *flags);
        }
        cpu_relax();
    }
}

/*
 * remove hrtimer, called with base lock held
 */
static inline int
remove_hrtimer(struct hrtimer *timer, struct hrtimer_clock_base *base,
               bool restart, bool keep_local)
{
    u8 state = timer->state;

    if (state & HRTIMER_STATE_ENQUEUED) {
        panic("%s: HRTIMER_STATE_ENQUEUED!\n", __func__);
    }
    return 0;
}

/*
 * Add two ktime values and do a safety check for overflow:
 */
ktime_t ktime_add_safe(const ktime_t lhs, const ktime_t rhs)
{
    ktime_t res = ktime_add_unsafe(lhs, rhs);

    /*
     * We use KTIME_SEC_MAX here, the maximum timeout which we can
     * return to user space in a timespec:
     */
    if (res < 0 || res < lhs || res < rhs)
        res = ktime_set(KTIME_SEC_MAX, 0);

    return res;
}

EXPORT_SYMBOL_GPL(ktime_add_safe);

static inline
ktime_t hrtimer_update_lowres(struct hrtimer *timer, ktime_t tim,
                              const enum hrtimer_mode mode)
{
    return tim;
}

static inline
struct hrtimer_cpu_base *get_target_base(struct hrtimer_cpu_base *base,
                     int pinned)
{
    if (static_branch_likely(&timers_migration_enabled) && !pinned)
        return &per_cpu(hrtimer_bases, get_nohz_timer_target());
    return base;
}

/*
 * We do not migrate the timer when it is expiring before the next
 * event on the target cpu. When high resolution is enabled, we cannot
 * reprogram the target cpu hardware and we would cause it to fire
 * late. To keep it simple, we handle the high resolution enabled and
 * disabled case similar.
 *
 * Called with cpu_base->lock of target cpu held.
 */
static int
hrtimer_check_target(struct hrtimer *timer,
                     struct hrtimer_clock_base *new_base)
{
    ktime_t expires;

    expires = ktime_sub(hrtimer_get_expires(timer), new_base->offset);
    return expires < new_base->cpu_base->expires_next;
}

/*
 * We switch the timer base to a power-optimized selected CPU target,
 * if:
 *  - NO_HZ_COMMON is enabled
 *  - timer migration is enabled
 *  - the timer callback is not running
 *  - the timer is not the first expiring timer on the new target
 *
 * If one of the above requirements is not fulfilled we move the timer
 * to the current CPU or leave it on the previously assigned CPU if
 * the timer callback is currently running.
 */
static inline struct hrtimer_clock_base *
switch_hrtimer_base(struct hrtimer *timer,
                    struct hrtimer_clock_base *base,
                    int pinned)
{
    struct hrtimer_cpu_base *new_cpu_base, *this_cpu_base;
    struct hrtimer_clock_base *new_base;
    int basenum = base->index;

    this_cpu_base = this_cpu_ptr(&hrtimer_bases);
    new_cpu_base = get_target_base(this_cpu_base, pinned);

 again:
    new_base = &new_cpu_base->clock_base[basenum];

    if (base != new_base) {
        panic("%s: 1!\n", __func__);
    } else {
        if (new_cpu_base != this_cpu_base &&
            hrtimer_check_target(timer, new_base)) {
            new_cpu_base = this_cpu_base;
            goto again;
        }
    }
    return new_base;
}

/*
 * enqueue_hrtimer - internal function to (re)start a timer
 *
 * The timer is inserted in expiry order. Insertion into the
 * red black tree is O(log(n)). Must hold the base lock.
 *
 * Returns 1 when the new timer is the leftmost timer in the tree.
 */
static int enqueue_hrtimer(struct hrtimer *timer,
                           struct hrtimer_clock_base *base,
                           enum hrtimer_mode mode)
{
    //debug_activate(timer, mode);

    base->cpu_base->active_bases |= 1 << base->index;

    /* Pairs with the lockless read in hrtimer_is_queued() */
    WRITE_ONCE(timer->state, HRTIMER_STATE_ENQUEUED);

    return timerqueue_add(&base->active, &timer->node);
}

static int __hrtimer_start_range_ns(struct hrtimer *timer,
                                    ktime_t tim,
                                    u64 delta_ns,
                                    const enum hrtimer_mode mode,
                                    struct hrtimer_clock_base *base)
{
    struct hrtimer_clock_base *new_base;
    bool force_local, first;

    /*
     * If the timer is on the local cpu base and is the first expiring
     * timer then this might end up reprogramming the hardware twice
     * (on removal and on enqueue). To avoid that by prevent the
     * reprogram on removal, keep the timer local to the current CPU
     * and enforce reprogramming after it is queued no matter whether
     * it is the new first expiring timer again or not.
     */
    force_local = base->cpu_base == this_cpu_ptr(&hrtimer_bases);
    force_local &= base->cpu_base->next_timer == timer;

    /*
     * Remove an active timer from the queue. In case it is not queued
     * on the current CPU, make sure that remove_hrtimer() updates the
     * remote data correctly.
     *
     * If it's on the current CPU and the first expiring timer, then
     * skip reprogramming, keep the timer local and enforce
     * reprogramming later if it was the first expiring timer.  This
     * avoids programming the underlying clock event twice (once at
     * removal and once after enqueue).
     */
    remove_hrtimer(timer, base, true, force_local);

    if (mode & HRTIMER_MODE_REL)
        tim = ktime_add_safe(tim, base->get_time());

    tim = hrtimer_update_lowres(timer, tim, mode);

    hrtimer_set_expires_range_ns(timer, tim, delta_ns);

    /* Switch the timer base, if necessary: */
    if (!force_local) {
        new_base = switch_hrtimer_base(timer, base,
                                       mode & HRTIMER_MODE_PINNED);
    } else {
        new_base = base;
    }

    first = enqueue_hrtimer(timer, new_base, mode);
    if (!force_local)
        return first;

    panic("%s: END!\n", __func__);
}

/*
 * Is the high resolution mode active ?
 */
static inline
int __hrtimer_hres_active(struct hrtimer_cpu_base *cpu_base)
{
    return cpu_base->hres_active;
}

static void __hrtimer_reprogram(struct hrtimer_cpu_base *cpu_base,
                                struct hrtimer *next_timer,
                                ktime_t expires_next)
{
    cpu_base->expires_next = expires_next;

    /*
     * If hres is not active, hardware does not have to be
     * reprogrammed yet.
     *
     * If a hang was detected in the last timer interrupt then we
     * leave the hang delay active in the hardware. We want the
     * system to make progress. That also prevents the following
     * scenario:
     * T1 expires 50ms from now
     * T2 expires 5s from now
     *
     * T1 is removed, so this code is called and would reprogram
     * the hardware to 5s from now. Any hrtimer_start after that
     * will not reprogram the hardware due to hang_detected being
     * set. So we'd effectively block all timers until the T2 event
     * fires.
     */
    if (!__hrtimer_hres_active(cpu_base) || cpu_base->hang_detected)
        return;

    panic("%s: END!\n", __func__);
}

/*
 * When a timer is enqueued and expires earlier than the already enqueued
 * timers, we have to check, whether it expires earlier than the timer for
 * which the clock event device was armed.
 *
 * Called with interrupts disabled and base->cpu_base.lock held
 */
static void hrtimer_reprogram(struct hrtimer *timer, bool reprogram)
{
    struct hrtimer_cpu_base *cpu_base = this_cpu_ptr(&hrtimer_bases);
    struct hrtimer_clock_base *base = timer->base;
    ktime_t expires = ktime_sub(hrtimer_get_expires(timer), base->offset);

    WARN_ON_ONCE(hrtimer_get_expires_tv64(timer) < 0);

    /*
     * CLOCK_REALTIME timer might be requested with an absolute
     * expiry time which is less than base->offset. Set it to 0.
     */
    if (expires < 0)
        expires = 0;

    if (timer->is_soft) {

        panic("%s: is_soft!\n", __func__);
    }

    /*
     * If the timer is not on the current cpu, we cannot reprogram
     * the other cpus clock event device.
     */
    if (base->cpu_base != cpu_base)
        return;

    if (expires >= cpu_base->expires_next)
        return;

    /*
     * If the hrtimer interrupt is running, then it will reevaluate the
     * clock bases and reprogram the clock event device.
     */
    if (cpu_base->in_hrtirq)
        return;

    cpu_base->next_timer = timer;

    __hrtimer_reprogram(cpu_base, timer, expires);
}

/*
 * Counterpart to lock_hrtimer_base above:
 */
static inline
void unlock_hrtimer_base(const struct hrtimer *timer,
                         unsigned long *flags)
{
    raw_spin_unlock_irqrestore(&timer->base->cpu_base->lock, *flags);
}

/**
 * hrtimer_start_range_ns - (re)start an hrtimer
 * @timer:  the timer to be added
 * @tim:    expiry time
 * @delta_ns:   "slack" range for the timer
 * @mode:   timer mode: absolute (HRTIMER_MODE_ABS) or
 *      relative (HRTIMER_MODE_REL), and pinned (HRTIMER_MODE_PINNED);
 *      softirq based mode is considered for debug purpose only!
 */
void hrtimer_start_range_ns(struct hrtimer *timer, ktime_t tim,
                            u64 delta_ns, const enum hrtimer_mode mode)
{
    struct hrtimer_clock_base *base;
    unsigned long flags;

    /*
     * Check whether the HRTIMER_MODE_SOFT bit and hrtimer.is_soft
     * match on CONFIG_PREEMPT_RT = n. With PREEMPT_RT check the hard
     * expiry mode because unmarked timers are moved to softirq expiry.
     */
    WARN_ON_ONCE(!(mode & HRTIMER_MODE_SOFT) ^ !timer->is_soft);

    base = lock_hrtimer_base(timer, &flags);

    if (__hrtimer_start_range_ns(timer, tim, delta_ns, mode, base))
        hrtimer_reprogram(timer, true);

    unlock_hrtimer_base(timer, &flags);
}

/*
 * Functions related to boot-time initialization:
 */
int hrtimers_prepare_cpu(unsigned int cpu)
{
    struct hrtimer_cpu_base *cpu_base = &per_cpu(hrtimer_bases, cpu);
    int i;

    for (i = 0; i < HRTIMER_MAX_CLOCK_BASES; i++) {
        struct hrtimer_clock_base *clock_b = &cpu_base->clock_base[i];

        clock_b->cpu_base = cpu_base;
        seqcount_raw_spinlock_init(&clock_b->seq, &cpu_base->lock);
        timerqueue_init_head(&clock_b->active);
    }

    cpu_base->cpu = cpu;
    cpu_base->active_bases = 0;
    cpu_base->hres_active = 0;
    cpu_base->hang_detected = 0;
    cpu_base->next_timer = NULL;
    cpu_base->softirq_next_timer = NULL;
    cpu_base->expires_next = KTIME_MAX;
    cpu_base->softirq_expires_next = KTIME_MAX;
    hrtimer_cpu_base_init_expiry_lock(cpu_base);
    return 0;
}

int hrtimers_dead_cpu(unsigned int scpu)
{
    panic("%s: END!\n", __func__);
}

/**
 * hrtimer_init - initialize a timer to the given clock
 * @timer:  the timer to be initialized
 * @clock_id:   the clock to be used
 * @mode:       The modes which are relevant for initialization:
 *              HRTIMER_MODE_ABS, HRTIMER_MODE_REL, HRTIMER_MODE_ABS_SOFT,
 *              HRTIMER_MODE_REL_SOFT
 *
 *              The PINNED variants of the above can be handed in,
 *              but the PINNED bit is ignored as pinning happens
 *              when the hrtimer is started
 */
void hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
                  enum hrtimer_mode mode)
{
    //debug_init(timer, clock_id, mode);
    __hrtimer_init(timer, clock_id, mode);
}
EXPORT_SYMBOL_GPL(hrtimer_init);

static __latent_entropy
void hrtimer_run_softirq(struct softirq_action *h)
{
    panic("%s: END!\n", __func__);
}

void __init hrtimers_init(void)
{
    hrtimers_prepare_cpu(smp_processor_id());
    open_softirq(HRTIMER_SOFTIRQ, hrtimer_run_softirq);
}
