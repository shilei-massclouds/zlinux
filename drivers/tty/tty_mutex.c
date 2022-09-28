// SPDX-License-Identifier: GPL-2.0
#include <linux/tty.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include "tty.h"

/* Legacy tty mutex glue */

/*
 * Getting the big tty mutex.
 */

void tty_lock(struct tty_struct *tty)
{
    if (WARN(tty->magic != TTY_MAGIC, "L Bad %p\n", tty))
        return;
    tty_kref_get(tty);
    mutex_lock(&tty->legacy_mutex);
}
EXPORT_SYMBOL(tty_lock);

void tty_unlock(struct tty_struct *tty)
{
    if (WARN(tty->magic != TTY_MAGIC, "U Bad %p\n", tty))
        return;
    mutex_unlock(&tty->legacy_mutex);
    tty_kref_put(tty);
}
EXPORT_SYMBOL(tty_unlock);
