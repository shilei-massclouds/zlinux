/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/linux/signalfd.h
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */
#ifndef _LINUX_SIGNALFD_H
#define _LINUX_SIGNALFD_H

//#include <uapi/linux/signalfd.h>
#include <linux/sched/signal.h>

/*
 * Deliver the signal to listening signalfd.
 */
static inline void signalfd_notify(struct task_struct *tsk, int sig)
{
    if (unlikely(waitqueue_active(&tsk->sighand->signalfd_wqh)))
        wake_up(&tsk->sighand->signalfd_wqh);
}

extern void signalfd_cleanup(struct sighand_struct *sighand);

#endif /* _LINUX_SIGNALFD_H */
