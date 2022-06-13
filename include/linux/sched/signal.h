/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_SIGNAL_H
#define _LINUX_SCHED_SIGNAL_H

/*
#include <linux/rculist.h>
#include <linux/signal.h>
*/
#include <linux/sched.h>
/*
#include <linux/sched/jobctl.h>
*/
#include <linux/sched/task.h>
//#include <linux/cred.h>
#include <linux/refcount.h>
//#include <linux/posix-timers.h>
#include <linux/mm_types.h>
#include <asm/ptrace.h>

/*
 * NOTE! "signal_struct" does not have its own
 * locking, because a shared signal_struct always
 * implies a shared sighand_struct, so locking
 * sighand_struct is always a proper superset of
 * the locking of signal_struct.
 */
struct signal_struct {
    unsigned int flags; /* see SIGNAL_* flags below */
} __randomize_layout;

#define SIGNAL_UNKILLABLE   0x00000040 /* for init: ignore fatal signals */

static inline int signal_pending(struct task_struct *p)
{
#if 0
    /*
     * TIF_NOTIFY_SIGNAL isn't really a signal, but it requires the same
     * behavior in terms of ensuring that we break out of wait loops
     * so that notify signal callbacks can be processed.
     */
    if (unlikely(test_tsk_thread_flag(p, TIF_NOTIFY_SIGNAL)))
        return 1;
    return task_sigpending(p);
#endif
    return 1;
}

static inline int
signal_pending_state(unsigned int state, struct task_struct *p)
{
#if 0
    if (!(state & (TASK_INTERRUPTIBLE | TASK_WAKEKILL)))
        return 0;
    if (!signal_pending(p))
        return 0;

    return (state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p);
#endif
    return 0;
}

#endif /* _LINUX_SCHED_SIGNAL_H */
