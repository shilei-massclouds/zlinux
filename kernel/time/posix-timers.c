// SPDX-License-Identifier: GPL-2.0+
/*
 * 2002-10-15  Posix Clocks & timers
 *                           by George Anzinger george@mvista.com
 *               Copyright (C) 2002 2003 by MontaVista Software.
 *
 * 2004-06-01  Fix CLOCK_REALTIME clock/timer TIMER_ABSTIME bug.
 *               Copyright (C) 2004 Boris Hu
 *
 * These are all the functions necessary to implement POSIX clocks & timers
 */
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/mutex.h>
#include <linux/sched/task.h>

#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/hash.h>
//#include <linux/posix-clock.h>
#include <linux/posix-timers.h>
#include <linux/syscalls.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/export.h>
#include <linux/hashtable.h>
#include <linux/compat.h>
//#include <linux/nospec.h>
//#include <linux/time_namespace.h>

#include "timekeeping.h"
//#include "posix-timers.h"

SYSCALL_DEFINE2(clock_gettime, const clockid_t, which_clock,
                struct __kernel_timespec __user *, tp)
{
#if 0
    const struct k_clock *kc = clockid_to_kclock(which_clock);
    struct timespec64 kernel_tp;
    int error;

    if (!kc)
        return -EINVAL;

    error = kc->clock_get_timespec(which_clock, &kernel_tp);

    if (!error && put_timespec64(&kernel_tp, tp))
        error = -EFAULT;

    return error;
#endif
    panic("%s: END!\n", __func__);
}

SYSCALL_DEFINE2(clock_getres, const clockid_t, which_clock,
                struct __kernel_timespec __user *, tp)
{
#if 0
    const struct k_clock *kc = clockid_to_kclock(which_clock);
    struct timespec64 rtn_tp;
    int error;

    if (!kc)
        return -EINVAL;

    error = kc->clock_getres(which_clock, &rtn_tp);

    if (!error && tp && put_timespec64(&rtn_tp, tp))
        error = -EFAULT;

    return error;
#endif
    panic("%s: END!\n", __func__);
}

