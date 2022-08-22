// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains functions which manage clock event devices.
 *
 * Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007, Timesys Corp., Thomas Gleixner
 */

#include <linux/clockchips.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/device.h>

#include "tick-internal.h"

/* The registered clock event devices */
static LIST_HEAD(clockevent_devices);
static LIST_HEAD(clockevents_released);
/* Protection for the above */
static DEFINE_RAW_SPINLOCK(clockevents_lock);
/* Protection for unbind operations */
static DEFINE_MUTEX(clockevents_mutex);

static u64 cev_delta2ns(unsigned long latch, struct clock_event_device *evt,
                        bool ismax)
{
    u64 clc = (u64) latch << evt->shift;
    u64 rnd;

    if (WARN_ON(!evt->mult))
        evt->mult = 1;
    rnd = (u64) evt->mult - 1;

    /*
     * Upper bound sanity check. If the backwards conversion is
     * not equal latch, we know that the above shift overflowed.
     */
    if ((clc >> evt->shift) != (u64)latch)
        clc = ~0ULL;

    /*
     * Scaled math oddities:
     *
     * For mult <= (1 << shift) we can safely add mult - 1 to
     * prevent integer rounding loss. So the backwards conversion
     * from nsec to device ticks will be correct.
     *
     * For mult > (1 << shift), i.e. device frequency is > 1GHz we
     * need to be careful. Adding mult - 1 will result in a value
     * which when converted back to device ticks can be larger
     * than latch by up to (mult - 1) >> shift. For the min_delta
     * calculation we still want to apply this in order to stay
     * above the minimum device ticks limit. For the upper limit
     * we would end up with a latch value larger than the upper
     * limit of the device, so we omit the add to stay below the
     * device upper boundary.
     *
     * Also omit the add if it would overflow the u64 boundary.
     */
    if ((~0ULL - clc > rnd) && (!ismax || evt->mult <= (1ULL << evt->shift)))
        clc += rnd;

    do_div(clc, evt->mult);

    /* Deltas less than 1usec are pointless noise */
    return clc > 1000 ? clc : 1000;
}

static void clockevents_config(struct clock_event_device *dev, u32 freq)
{
    u64 sec;

    if (!(dev->features & CLOCK_EVT_FEAT_ONESHOT))
        return;

    /*
     * Calculate the maximum number of seconds we can sleep. Limit
     * to 10 minutes for hardware which can program more than
     * 32bit ticks so we still get reasonable conversion values.
     */
    sec = dev->max_delta_ticks;
    do_div(sec, freq);
    if (!sec)
        sec = 1;
    else if (sec > 600 && dev->max_delta_ticks > UINT_MAX)
        sec = 600;

    clockevents_calc_mult_shift(dev, freq, sec);
    dev->min_delta_ns = cev_delta2ns(dev->min_delta_ticks, dev, false);
    dev->max_delta_ns = cev_delta2ns(dev->max_delta_ticks, dev, true);
}

/*
 * Called after a notify add to make devices available which were
 * released from the notifier call.
 */
static void clockevents_notify_released(void)
{
    struct clock_event_device *dev;

    while (!list_empty(&clockevents_released)) {
        dev = list_entry(clockevents_released.next,
                         struct clock_event_device, list);
        list_move(&dev->list, &clockevent_devices);
        tick_check_new_device(dev);
    }
}

/**
 * clockevents_register_device - register a clock event device
 * @dev:    device to register
 */
void clockevents_register_device(struct clock_event_device *dev)
{
    unsigned long flags;

    /* Initialize state to DETACHED */
    clockevent_set_state(dev, CLOCK_EVT_STATE_DETACHED);

    if (!dev->cpumask) {
        WARN_ON(num_possible_cpus() > 1);
        dev->cpumask = cpumask_of(smp_processor_id());
    }

    if (dev->cpumask == cpu_all_mask) {
        WARN(1, "%s cpumask == cpu_all_mask, using cpu_possible_mask instead\n",
             dev->name);
        dev->cpumask = cpu_possible_mask;
    }

    raw_spin_lock_irqsave(&clockevents_lock, flags);

    list_add(&dev->list, &clockevent_devices);
    tick_check_new_device(dev);
    clockevents_notify_released();

    raw_spin_unlock_irqrestore(&clockevents_lock, flags);
}

/**
 * clockevents_config_and_register - Configure and register a clock event device
 * @dev:    device to register
 * @freq:   The clock frequency
 * @min_delta:  The minimum clock ticks to program in oneshot mode
 * @max_delta:  The maximum clock ticks to program in oneshot mode
 *
 * min/max_delta can be 0 for devices which do not support oneshot mode.
 */
void clockevents_config_and_register(struct clock_event_device *dev,
                                     u32 freq, unsigned long min_delta,
                                     unsigned long max_delta)
{
    dev->min_delta_ticks = min_delta;
    dev->max_delta_ticks = max_delta;
    clockevents_config(dev, freq);
    clockevents_register_device(dev);
}
EXPORT_SYMBOL_GPL(clockevents_config_and_register);

static int __clockevents_switch_state(struct clock_event_device *dev,
                                      enum clock_event_state state)
{
    if (dev->features & CLOCK_EVT_FEAT_DUMMY)
        return 0;

    /* Transition with new state-specific callbacks */
    switch (state) {
    case CLOCK_EVT_STATE_DETACHED:
        /* The clockevent device is getting replaced. Shut it down. */

    case CLOCK_EVT_STATE_SHUTDOWN:
        if (dev->set_state_shutdown)
            return dev->set_state_shutdown(dev);
        return 0;

    case CLOCK_EVT_STATE_PERIODIC:
        /* Core internal bug */
        if (!(dev->features & CLOCK_EVT_FEAT_PERIODIC))
            return -ENOSYS;
        if (dev->set_state_periodic)
            return dev->set_state_periodic(dev);
        return 0;

    case CLOCK_EVT_STATE_ONESHOT:
        /* Core internal bug */
        if (!(dev->features & CLOCK_EVT_FEAT_ONESHOT))
            return -ENOSYS;
        if (dev->set_state_oneshot)
            return dev->set_state_oneshot(dev);
        return 0;

    case CLOCK_EVT_STATE_ONESHOT_STOPPED:
        /* Core internal bug */
        if (WARN_ONCE(!clockevent_state_oneshot(dev), "Current state: %d\n",
                      clockevent_get_state(dev)))
            return -EINVAL;

        if (dev->set_state_oneshot_stopped)
            return dev->set_state_oneshot_stopped(dev);
        else
            return -ENOSYS;

    default:
        return -ENOSYS;
    }
}

/**
 * clockevents_switch_state - set the operating state of a clock event device
 * @dev:    device to modify
 * @state:  new state
 *
 * Must be called with interrupts disabled !
 */
void clockevents_switch_state(struct clock_event_device *dev,
                              enum clock_event_state state)
{
    if (clockevent_get_state(dev) != state) {
        if (__clockevents_switch_state(dev, state))
            return;

        clockevent_set_state(dev, state);

        /*
         * A nsec2cyc multiplicator of 0 is invalid and we'd crash
         * on it, so fix it up and emit a warning:
         */
        if (clockevent_state_oneshot(dev)) {
            if (WARN_ON(!dev->mult))
                dev->mult = 1;
        }
    }
}

/**
 * clockevents_shutdown - shutdown the device and clear next_event
 * @dev:    device to shutdown
 */
void clockevents_shutdown(struct clock_event_device *dev)
{
    clockevents_switch_state(dev, CLOCK_EVT_STATE_SHUTDOWN);
    dev->next_event = KTIME_MAX;
}

/**
 * clockevents_exchange_device - release and request clock devices
 * @old:    device to release (can be NULL)
 * @new:    device to request (can be NULL)
 *
 * Called from various tick functions with clockevents_lock held and
 * interrupts disabled.
 */
void clockevents_exchange_device(struct clock_event_device *old,
                 struct clock_event_device *new)
{
    /*
     * Caller releases a clock event device. We queue it into the
     * released list and do a notify add later.
     */
    if (old) {
        module_put(old->owner);
        clockevents_switch_state(old, CLOCK_EVT_STATE_DETACHED);
        list_move(&old->list, &clockevents_released);
    }

    if (new) {
        BUG_ON(!clockevent_state_detached(new));
        clockevents_shutdown(new);
    }
}

/*
 * Noop handler when we shut down an event device
 */
void clockevents_handle_noop(struct clock_event_device *dev)
{
}

/**
 * clockevents_program_min_delta - Set clock event device to the minimum delay.
 * @dev:    device to program
 *
 * Returns 0 on success, -ETIME when the retry loop failed.
 */
static int clockevents_program_min_delta(struct clock_event_device *dev)
{
    unsigned long long clc;
    int64_t delta;
    int i;

    panic("%s: END!\n", __func__);
}

/**
 * clockevents_program_event - Reprogram the clock event device.
 * @dev:    device to program
 * @expires:    absolute expiry time (monotonic clock)
 * @force:  program minimum delay if expires can not be set
 *
 * Returns 0 on success, -ETIME when the event is in the past.
 */
int clockevents_program_event(struct clock_event_device *dev, ktime_t expires,
                              bool force)
{
    unsigned long long clc;
    int64_t delta;
    int rc;

    if (WARN_ON_ONCE(expires < 0))
        return -ETIME;

    dev->next_event = expires;

    if (clockevent_state_shutdown(dev))
        return 0;

    /* We must be in ONESHOT state here */
    WARN_ONCE(!clockevent_state_oneshot(dev), "Current state: %d\n",
              clockevent_get_state(dev));

    /* Shortcut for clockevent devices that can deal with ktime. */
    if (dev->features & CLOCK_EVT_FEAT_KTIME)
        return dev->set_next_ktime(expires, dev);

    delta = ktime_to_ns(ktime_sub(expires, ktime_get()));
    if (delta <= 0)
        return force ? clockevents_program_min_delta(dev) : -ETIME;

    delta = min(delta, (int64_t) dev->max_delta_ns);
    delta = max(delta, (int64_t) dev->min_delta_ns);

    clc = ((unsigned long long) delta * dev->mult) >> dev->shift;
    rc = dev->set_next_event((unsigned long) clc, dev);

    return (rc && force) ? clockevents_program_min_delta(dev) : rc;
}
