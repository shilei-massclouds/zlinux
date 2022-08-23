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
//#include <linux/irq_work.h>
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
