// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains the base functions to manage periodic tick
 * related events.
 *
 * Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007, Timesys Corp., Thomas Gleixner
 */
#include <linux/cpu.h>
#include <linux/err.h>
//#include <linux/hrtimer.h>
#include <linux/interrupt.h>
//#include <linux/nmi.h>
#include <linux/percpu.h>
//#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/module.h>
//#include <trace/events/power.h>

#include <asm/irq_regs.h>

#include "tick-internal.h"

int tick_do_timer_cpu __read_mostly = TICK_DO_TIMER_BOOT;

/*
 * Tick devices
 */
DEFINE_PER_CPU(struct tick_device, tick_cpu_device);
/*
 * Tick next event: keeps track of the tick time. It's updated by the
 * CPU which handles the tick and protected by jiffies_lock. There is
 * no requirement to write hold the jiffies seqcount for it.
 */
ktime_t tick_next_period;

__cacheline_aligned_in_smp DEFINE_RAW_SPINLOCK(jiffies_lock);
__cacheline_aligned_in_smp seqcount_raw_spinlock_t jiffies_seq =
    SEQCNT_RAW_SPINLOCK_ZERO(jiffies_seq, &jiffies_lock);

static bool tick_check_percpu(struct clock_event_device *curdev,
                              struct clock_event_device *newdev, int cpu)
{
    if (!cpumask_test_cpu(cpu, newdev->cpumask))
        return false;
    if (cpumask_equal(newdev->cpumask, cpumask_of(cpu)))
        return true;
    /* Check if irq affinity can be set */
    if (newdev->irq >= 0 && !irq_can_set_affinity(newdev->irq))
        return false;
    /* Prefer an existing cpu local device */
    if (curdev && cpumask_equal(curdev->cpumask, cpumask_of(cpu)))
        return false;
    return true;
}

static bool tick_check_preferred(struct clock_event_device *curdev,
                                 struct clock_event_device *newdev)
{
    /* Prefer oneshot capable device */
    if (!(newdev->features & CLOCK_EVT_FEAT_ONESHOT)) {
        if (curdev && (curdev->features & CLOCK_EVT_FEAT_ONESHOT))
            return false;
        if (tick_oneshot_mode_active())
            return false;
    }

    /*
     * Use the higher rated one, but prefer a CPU local device with a lower
     * rating than a non-CPU local device
     */
    return !curdev || newdev->rating > curdev->rating ||
           !cpumask_equal(curdev->cpumask, newdev->cpumask);
}

/*
 * Check whether the new device is a better fit than curdev. curdev
 * can be NULL !
 */
bool tick_check_replacement(struct clock_event_device *curdev,
                            struct clock_event_device *newdev)
{
    if (!tick_check_percpu(curdev, newdev, smp_processor_id()))
        return false;

    return tick_check_preferred(curdev, newdev);
}

/*
 * Setup the device for a periodic tick
 */
void tick_setup_periodic(struct clock_event_device *dev, int broadcast)
{
    tick_set_periodic_handler(dev, broadcast);

    /* Broadcast setup ? */
    if (!tick_device_is_functional(dev))
        return;

    if ((dev->features & CLOCK_EVT_FEAT_PERIODIC) &&
        !tick_broadcast_oneshot_active()) {
        panic("%s: 1\n", __func__);
    } else {
        unsigned int seq;
        ktime_t next;

        do {
            seq = read_seqcount_begin(&jiffies_seq);
            next = tick_next_period;
        } while (read_seqcount_retry(&jiffies_seq, seq));

        clockevents_switch_state(dev, CLOCK_EVT_STATE_ONESHOT);

        for (;;) {
            if (!clockevents_program_event(dev, next, false))
                return;
            next = ktime_add_ns(next, TICK_NSEC);
        }
    }
}

/*
 * Setup the tick device
 */
static void tick_setup_device(struct tick_device *td,
                              struct clock_event_device *newdev, int cpu,
                              const struct cpumask *cpumask)
{
    void (*handler)(struct clock_event_device *) = NULL;
    ktime_t next_event = 0;

    /*
     * First device setup ?
     */
    if (!td->evtdev) {
        /*
         * If no cpu took the do_timer update, assign it to
         * this cpu:
         */
        if (tick_do_timer_cpu == TICK_DO_TIMER_BOOT) {
            tick_do_timer_cpu = cpu;

            tick_next_period = ktime_get();
        }

        /*
         * Startup in periodic mode first.
         */
        td->mode = TICKDEV_MODE_PERIODIC;
    } else {
        handler = td->evtdev->event_handler;
        next_event = td->evtdev->next_event;
        td->evtdev->event_handler = clockevents_handle_noop;
    }

    td->evtdev = newdev;

    /*
     * When the device is not per cpu, pin the interrupt to the
     * current cpu:
     */
    if (!cpumask_equal(newdev->cpumask, cpumask))
        irq_set_affinity(newdev->irq, cpumask);

    /*
     * When global broadcasting is active, check if the current
     * device is registered as a placeholder for broadcast mode.
     * This allows us to handle this x86 misfeature in a generic
     * way. This function also returns !=0 when we keep the
     * current active broadcast state for this CPU.
     */
    if (tick_device_uses_broadcast(newdev, cpu))
        return;

    if (td->mode == TICKDEV_MODE_PERIODIC)
        tick_setup_periodic(newdev, 0);
    else
        tick_setup_oneshot(newdev, handler, next_event);
}

/*
 * Check, if the new registered device should be used. Called with
 * clockevents_lock held and interrupts disabled.
 */
void tick_check_new_device(struct clock_event_device *newdev)
{
    struct clock_event_device *curdev;
    struct tick_device *td;
    int cpu;

    cpu = smp_processor_id();
    td = &per_cpu(tick_cpu_device, cpu);
    curdev = td->evtdev;

    if (!tick_check_replacement(curdev, newdev))
        goto out_bc;

    if (!try_module_get(newdev->owner))
        return;

    /*
     * Replace the eventually existing device by the new
     * device. If the current device is the broadcast device, do
     * not give it back to the clockevents layer !
     */
    if (tick_is_broadcast_device(curdev)) {
        clockevents_shutdown(curdev);
        curdev = NULL;
    }
    clockevents_exchange_device(curdev, newdev);
    tick_setup_device(td, newdev, cpu, cpumask_of(cpu));
#if 0
    if (newdev->features & CLOCK_EVT_FEAT_ONESHOT)
        tick_oneshot_notify();
#endif
    return;

 out_bc:
    /*
     * Can the new device be used as a broadcast device ?
     */
    tick_install_broadcast_device(newdev, cpu);
}

/*
 * Periodic tick
 */
static void tick_periodic(int cpu)
{
    if (tick_do_timer_cpu == cpu) {
        raw_spin_lock(&jiffies_lock);
        write_seqcount_begin(&jiffies_seq);

        /* Keep track of the next tick event */
        tick_next_period = ktime_add_ns(tick_next_period, TICK_NSEC);

        do_timer(1);
        write_seqcount_end(&jiffies_seq);
        raw_spin_unlock(&jiffies_lock);
        update_wall_time();
    }

#if 0
    update_process_times(user_mode(get_irq_regs()));
    profile_tick(CPU_PROFILING);
#endif
}

/*
 * Event handler for periodic ticks
 */
void tick_handle_periodic(struct clock_event_device *dev)
{
    int cpu = smp_processor_id();
    ktime_t next = dev->next_event;

    tick_periodic(cpu);

    /*
     * The cpu might have transitioned to HIGHRES or NOHZ mode via
     * update_process_times() -> run_local_timers() ->
     * hrtimer_run_queues().
     */
    if (dev->event_handler != tick_handle_periodic)
        return;

    if (!clockevent_state_oneshot(dev))
        return;
    for (;;) {
        /*
         * Setup the next period for devices, which do not have
         * periodic mode:
         */
        next = ktime_add_ns(next, TICK_NSEC);

        if (!clockevents_program_event(dev, next, false))
            return;
        /*
         * Have to be careful here. If we're in oneshot mode,
         * before we call tick_periodic() in a loop, we need
         * to be sure we're using a real hardware clocksource.
         * Otherwise we could get trapped in an infinite
         * loop, as the tick_periodic() increments jiffies,
         * which then will increment time, possibly causing
         * the loop to trigger again and again.
         */
        if (timekeeping_valid_for_hres())
            tick_periodic(cpu);
    }


    panic("%s: END!\n", __func__);
}
