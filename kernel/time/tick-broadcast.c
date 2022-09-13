// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains functions which emulate a local clock-event
 * device via a broadcast event source.
 *
 * Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007, Timesys Corp., Thomas Gleixner
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
//#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/module.h>

#include "tick-internal.h"

static struct tick_device tick_broadcast_device;
static cpumask_var_t tick_broadcast_mask __cpumask_var_read_mostly;
static cpumask_var_t tick_broadcast_on __cpumask_var_read_mostly;

static __cacheline_aligned_in_smp DEFINE_RAW_SPINLOCK(tick_broadcast_lock);

static cpumask_var_t tick_broadcast_oneshot_mask
    __cpumask_var_read_mostly;
static cpumask_var_t tick_broadcast_pending_mask
    __cpumask_var_read_mostly;
static cpumask_var_t tick_broadcast_force_mask
    __cpumask_var_read_mostly;

/*
 * Conditionally install/replace broadcast device
 */
void tick_install_broadcast_device(struct clock_event_device *dev, int cpu)
{
    struct clock_event_device *cur = tick_broadcast_device.evtdev;

#if 0
    if (tick_set_oneshot_wakeup_device(dev, cpu))
        return;
#endif

    panic("%s: END!\n", __func__);
}

/*
 * Check, if the device is the broadcast device
 */
int tick_is_broadcast_device(struct clock_event_device *dev)
{
    return (dev && tick_broadcast_device.evtdev == dev);
}

static void err_broadcast(const struct cpumask *mask)
{
    pr_crit_once("Failed to broadcast timer tick. "
                 "Some CPUs may be unresponsive.\n");
}

static void tick_device_setup_broadcast_func(struct clock_event_device *dev)
{
    if (!dev->broadcast)
        dev->broadcast = tick_broadcast;
    if (!dev->broadcast) {
        pr_warn_once("%s depends on broadcast, "
                     "but no broadcast function available\n",
                     dev->name);
        dev->broadcast = err_broadcast;
    }
}

/*
 * Check, if the device is dysfunctional and a placeholder, which
 * needs to be handled by the broadcast device.
 */
int tick_device_uses_broadcast(struct clock_event_device *dev, int cpu)
{
    struct clock_event_device *bc = tick_broadcast_device.evtdev;
    unsigned long flags;
    int ret = 0;

    raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

    /*
     * Devices might be registered with both periodic and oneshot
     * mode disabled. This signals, that the device needs to be
     * operated from the broadcast device and is a placeholder for
     * the cpu local device.
     */
    if (!tick_device_is_functional(dev)) {
        panic("%s: !tick_device_is_functional!\n", __func__);
    } else {
        /*
         * Clear the broadcast bit for this cpu if the
         * device is not power state affected.
         */
        if (!(dev->features & CLOCK_EVT_FEAT_C3STOP))
            cpumask_clear_cpu(cpu, tick_broadcast_mask);
        else
            tick_device_setup_broadcast_func(dev);

        /*
         * Clear the broadcast bit if the CPU is not in
         * periodic broadcast on state.
         */
        if (!cpumask_test_cpu(cpu, tick_broadcast_on))
            cpumask_clear_cpu(cpu, tick_broadcast_mask);

        switch (tick_broadcast_device.mode) {
        case TICKDEV_MODE_ONESHOT:
#if 0
            /*
             * If the system is in oneshot mode we can
             * unconditionally clear the oneshot mask bit,
             * because the CPU is running and therefore
             * not in an idle state which causes the power
             * state affected device to stop. Let the
             * caller initialize the device.
             */
            tick_broadcast_clear_oneshot(cpu);
#endif
            panic("%s: 1!\n", __func__);
            ret = 0;
            break;

        case TICKDEV_MODE_PERIODIC:
            /*
             * If the system is in periodic mode, check
             * whether the broadcast device can be
             * switched off now.
             */
            if (cpumask_empty(tick_broadcast_mask) && bc)
                clockevents_shutdown(bc);
            /*
             * If we kept the cpu in the broadcast mask,
             * tell the caller to leave the per cpu device
             * in shutdown state. The periodic interrupt
             * is delivered by the broadcast device, if
             * the broadcast device exists and is not
             * hrtimer based.
             */
            if (bc && !(bc->features & CLOCK_EVT_FEAT_HRTIMER))
                ret = cpumask_test_cpu(cpu, tick_broadcast_mask);
            break;
        default:
            break;
        }
    }

    raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
    return ret;
}

/*
 * Event handler for periodic broadcast ticks
 */
static void
tick_handle_periodic_broadcast(struct clock_event_device *dev)
{
    panic("%s: END!\n", __func__);
}

/*
 * Set the periodic handler depending on broadcast on/off
 */
void tick_set_periodic_handler(struct clock_event_device *dev, int broadcast)
{
    if (!broadcast)
        dev->event_handler = tick_handle_periodic;
    else
        dev->event_handler = tick_handle_periodic_broadcast;
}

/*
 * Check, whether the broadcast device is in one shot mode
 */
int tick_broadcast_oneshot_active(void)
{
    return tick_broadcast_device.mode == TICKDEV_MODE_ONESHOT;
}

/*
 * Called before going idle with interrupts disabled. Checks whether a
 * broadcast event from the other core is about to happen. We detected
 * that in tick_broadcast_oneshot_control(). The callsite can use this
 * to avoid a deep idle transition as we are about to get the
 * broadcast IPI right away.
 */
int tick_check_broadcast_expired(void)
{
    return cpumask_test_cpu(smp_processor_id(),
                            tick_broadcast_force_mask);
}
