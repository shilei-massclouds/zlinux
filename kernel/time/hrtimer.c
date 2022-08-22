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
#include <linux/notifier.h>
#include <linux/syscalls.h>
#include <linux/interrupt.h>
#include <linux/tick.h>
#include <linux/err.h>
#include <linux/debugobjects.h>
#include <linux/sched/signal.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/sched/deadline.h>
#include <linux/sched/nohz.h>
#include <linux/sched/debug.h>
#include <linux/timer.h>
#include <linux/freezer.h>
#include <linux/compat.h>

#include <linux/uaccess.h>

#include <trace/events/timer.h>

#include "tick-internal.h"

/*
 * Called from timekeeping code to reprogram the hrtimer interrupt device
 * on all cpus and to notify timerfd.
 */
void clock_was_set_delayed(void)
{
    //schedule_work(&hrtimer_work);
    panic("%s: END!\n", __func__);
}
