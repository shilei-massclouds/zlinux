// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992 Darren Senn
 */

/* These are all the functions necessary to implement itimers */

#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/sched/signal.h>
#include <linux/sched/cputime.h>
#include <linux/posix-timers.h>
#include <linux/hrtimer.h>
#include <linux/compat.h>

#include <linux/uaccess.h>

/*
 * The timer is automagically restarted, when interval != 0
 */
enum hrtimer_restart it_real_fn(struct hrtimer *timer)
{
#if 0
    struct signal_struct *sig =
        container_of(timer, struct signal_struct, real_timer);
    struct pid *leader_pid = sig->pids[PIDTYPE_TGID];

    trace_itimer_expire(ITIMER_REAL, leader_pid, 0);
    kill_pid_info(SIGALRM, SEND_SIG_PRIV, leader_pid);

    return HRTIMER_NORESTART;
#endif
    panic("%s: END!\n", __func__);
}
