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
