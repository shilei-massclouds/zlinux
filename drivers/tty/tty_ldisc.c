// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/wait.h>
#include <linux/bitops.h>
//#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/ratelimit.h>
#include "tty.h"

/*
 *  This guards the refcounted line discipline lists. The lock
 *  must be taken with irqs off because there are hangup path
 *  callers who will do ldisc lookups and cannot sleep.
 */

static DEFINE_RAW_SPINLOCK(tty_ldiscs_lock);
/* Line disc dispatch table */
static struct tty_ldisc_ops *tty_ldiscs[NR_LDISCS];

/**
 * tty_register_ldisc   -   install a line discipline
 * @new_ldisc: pointer to the ldisc object
 *
 * Installs a new line discipline into the kernel. The discipline is set up as
 * unreferenced and then made available to the kernel from this point onwards.
 *
 * Locking: takes %tty_ldiscs_lock to guard against ldisc races
 */
int tty_register_ldisc(struct tty_ldisc_ops *new_ldisc)
{
    unsigned long flags;
    int ret = 0;

    if (new_ldisc->num < N_TTY || new_ldisc->num >= NR_LDISCS)
        return -EINVAL;

    raw_spin_lock_irqsave(&tty_ldiscs_lock, flags);
    tty_ldiscs[new_ldisc->num] = new_ldisc;
    raw_spin_unlock_irqrestore(&tty_ldiscs_lock, flags);

    return ret;
}
EXPORT_SYMBOL(tty_register_ldisc);
