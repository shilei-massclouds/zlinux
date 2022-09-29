// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/tty.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include "tty.h"

struct tty_struct *get_current_tty(void)
{
    struct tty_struct *tty;
    unsigned long flags;

    spin_lock_irqsave(&current->sighand->siglock, flags);
    tty = tty_kref_get(current->signal->tty);
    spin_unlock_irqrestore(&current->sighand->siglock, flags);
    return tty;
}
EXPORT_SYMBOL_GPL(get_current_tty);

/**
 *  __tty_check_change  -   check for POSIX terminal changes
 *  @tty: tty to check
 *  @sig: signal to send
 *
 *  If we try to write to, or set the state of, a terminal and we're
 *  not in the foreground, send a SIGTTOU.  If the signal is blocked or
 *  ignored, go ahead and perform the operation.  (POSIX 7.2)
 *
 *  Locking: ctrl.lock
 */
int __tty_check_change(struct tty_struct *tty, int sig)
{
    panic("%s: END!\n", __func__);
}

int tty_check_change(struct tty_struct *tty)
{
    return __tty_check_change(tty, SIGTTOU);
}
EXPORT_SYMBOL(tty_check_change);
