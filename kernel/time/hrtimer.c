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
//#include <linux/sched/nohz.h>
#include <linux/sched/debug.h>
//#include <linux/timer.h>
//#include <linux/freezer.h>
#include <linux/compat.h>

#include <linux/uaccess.h>

#include "tick-internal.h"

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
