// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains functions which manage high resolution tick
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
#include <linux/percpu.h>
//#include <linux/profile.h>
#include <linux/sched.h>

#include "tick-internal.h"

/**
 * tick_check_oneshot_mode - check whether the system is in oneshot mode
 *
 * returns 1 when either nohz or highres are enabled. otherwise 0.
 */
int tick_oneshot_mode_active(void)
{
    unsigned long flags;
    int ret;

    local_irq_save(flags);
    ret = __this_cpu_read(tick_cpu_device.mode) == TICKDEV_MODE_ONESHOT;
    local_irq_restore(flags);

    return ret;
}

/**
 * tick_setup_oneshot - setup the event device for oneshot mode (hres or nohz)
 */
void tick_setup_oneshot(struct clock_event_device *newdev,
                        void (*handler)(struct clock_event_device *),
                        ktime_t next_event)
{
    newdev->event_handler = handler;
    clockevents_switch_state(newdev, CLOCK_EVT_STATE_ONESHOT);
    clockevents_program_event(newdev, next_event, true);
}
