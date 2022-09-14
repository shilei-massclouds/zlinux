// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 *  Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 *  Copyright(C) 2006-2007  Timesys Corp., Thomas Gleixner
 *
 *  No idle tick implementation for low and high resolution timers
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/percpu.h>
#if 0
#include <linux/nmi.h>
#include <linux/profile.h>
#endif
#include <linux/sched/signal.h>
#include <linux/sched/clock.h>
#if 0
#include <linux/sched/stat.h>
#include <linux/sched/nohz.h>
#endif
#include <linux/sched/loadavg.h>
#include <linux/module.h>
#include <linux/irq_work.h>
#include <linux/posix-timers.h>
//#include <linux/context_tracking.h>
#include <linux/mm.h>

#include <asm/irq_regs.h>

#include "tick-internal.h"

/*
 * Per-CPU nohz control structure
 */
static DEFINE_PER_CPU(struct tick_sched, tick_cpu_sched);

/*
 * Async notification about clocksource changes
 */
void tick_clock_notify(void)
{
    int cpu;

    for_each_possible_cpu(cpu)
        set_bit(0, &per_cpu(tick_cpu_sched, cpu).check_clocks);
}

static void tick_nohz_start_idle(struct tick_sched *ts)
{
    ts->idle_entrytime = ktime_get();
    ts->idle_active = 1;
    sched_clock_idle_sleep_event();
}

/**
 * tick_nohz_idle_enter - prepare for entering idle on the current CPU
 *
 * Called when we start the idle loop.
 */
void tick_nohz_idle_enter(void)
{
    struct tick_sched *ts;

    local_irq_disable();

    ts = this_cpu_ptr(&tick_cpu_sched);

    WARN_ON_ONCE(ts->timer_expires_base);

    ts->inidle = 1;
    tick_nohz_start_idle(ts);

    local_irq_enable();
}

/**
 * tick_nohz_idle_exit - restart the idle tick from the idle task
 *
 * Restart the idle tick when the CPU is woken up from idle
 * This also exit the RCU extended quiescent state. The CPU
 * can use RCU again after this function is called.
 */
void tick_nohz_idle_exit(void)
{
    panic("%s: END!\n", __func__);
}

void tick_nohz_idle_restart_tick(void)
{
    struct tick_sched *ts = this_cpu_ptr(&tick_cpu_sched);

    if (ts->tick_stopped) {
#if 0
        ktime_t now = ktime_get();
        tick_nohz_restart_sched_tick(ts, now);
        tick_nohz_account_idle_time(ts, now);
#endif
        panic("%s: END!\n", __func__);
    }
}

/*
 * A pending softirq outside an IRQ (or softirq disabled section) context
 * should be waiting for ksoftirqd to handle it. Therefore we shouldn't
 * reach here due to the need_resched() early check in can_stop_idle_tick().
 *
 * However if we are between CPUHP_AP_SMPBOOT_THREADS and CPU_TEARDOWN_CPU on the
 * cpu_down() process, softirqs can still be raised while ksoftirqd is parked,
 * triggering the below since wakep_softirqd() is ignored.
 *
 */
static bool report_idle_softirq(void)
{
    static int ratelimit;
    unsigned int pending = local_softirq_pending();

    if (likely(!pending))
        return false;

    panic("%s: END!\n", __func__);
}

static bool can_stop_idle_tick(int cpu, struct tick_sched *ts)
{
    /*
     * If this CPU is offline and it is the one which updates
     * jiffies, then give up the assignment and let it be taken by
     * the CPU which runs the tick timer next. If we don't drop
     * this here the jiffies might be stale and do_timer() never
     * invoked.
     */
    if (unlikely(!cpu_online(cpu))) {
        panic("%s: 1!\n", __func__);
    }

    printk("######### %s: 1 ts(%lx)\n", __func__, ts);
    if (unlikely(ts->nohz_mode == NOHZ_MODE_INACTIVE))
        return false;

    if (need_resched())
        return false;

    if (unlikely(report_idle_softirq()))
        return false;

    panic("%s: END!\n", __func__);
}

static ktime_t tick_nohz_next_event(struct tick_sched *ts, int cpu)
{
    panic("%s: END!\n", __func__);
}

static void __tick_nohz_idle_stop_tick(struct tick_sched *ts)
{
    ktime_t expires;
    int cpu = smp_processor_id();

    /*
     * If tick_nohz_get_sleep_length() ran tick_nohz_next_event(), the
     * tick timer expiration time is known already.
     */
    if (ts->timer_expires_base)
        expires = ts->timer_expires;
    else if (can_stop_idle_tick(cpu, ts))
        expires = tick_nohz_next_event(ts, cpu);
    else
        return;

    panic("%s: END!\n", __func__);
}

/**
 * tick_nohz_idle_stop_tick - stop the idle tick from the idle task
 *
 * When the next event is more than a tick into the future, stop the idle tick
 */
void tick_nohz_idle_stop_tick(void)
{
    __tick_nohz_idle_stop_tick(this_cpu_ptr(&tick_cpu_sched));
    printk("%s: END!\n", __func__);
}
