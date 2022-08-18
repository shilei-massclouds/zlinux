// SPDX-License-Identifier: GPL-2.0
/*
 * Generic sched_clock() support, to extend low level hardware time
 * counters to full 64-bit ns values.
 */
#include <linux/clocksource.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#if 0
#include <linux/sched/clock.h>
#include <linux/syscore_ops.h>
#include <linux/hrtimer.h>
#endif
#include <linux/sched_clock.h>
#include <linux/seqlock.h>
#include <linux/bitops.h>

//#include "timekeeping.h"

void __init
sched_clock_register(u64 (*read)(void), int bits, unsigned long rate)
{
    u64 res, wrap, new_mask, new_epoch, cyc, ns;
    u32 new_mult, new_shift;
    unsigned long r, flags;
    char r_unit;
    struct clock_read_data rd;

    panic("%s: END!\n", __func__);
}
