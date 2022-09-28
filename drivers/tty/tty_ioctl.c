// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 * Modified by Fred N. van Kempen, 01/29/93, to add line disciplines
 * which can be dynamically activated and de-activated by the line
 * discipline handling modules (like SLIP).
 */

#include <linux/types.h>
#include <linux/termios.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/tty.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/compat.h>
#include "tty.h"

#include <asm/io.h>
#include <linux/uaccess.h>

/**
 *  tty_get_char_size   -   get size of a character
 *  @cflag: termios cflag value
 *
 *  Get the size (in bits) of a character depending on @cflag's %CSIZE
 *  setting.
 */
unsigned char tty_get_char_size(unsigned int cflag)
{
    switch (cflag & CSIZE) {
    case CS5:
        return 5;
    case CS6:
        return 6;
    case CS7:
        return 7;
    case CS8:
    default:
        return 8;
    }
}
EXPORT_SYMBOL_GPL(tty_get_char_size);

/**
 *  tty_get_frame_size  -   get size of a frame
 *  @cflag: termios cflag value
 *
 *  Get the size (in bits) of a frame depending on @cflag's %CSIZE, %CSTOPB,
 *  and %PARENB setting. The result is a sum of character size, start and
 *  stop bits -- one bit each -- second stop bit (if set), and parity bit
 *  (if set).
 */
unsigned char tty_get_frame_size(unsigned int cflag)
{
    unsigned char bits = 2 + tty_get_char_size(cflag);

    if (cflag & CSTOPB)
        bits++;
    if (cflag & PARENB)
        bits++;

    return bits;
}
EXPORT_SYMBOL_GPL(tty_get_frame_size);

/**
 *  tty_unthrottle      -   flow control
 *  @tty: terminal
 *
 *  Indicate that a tty may continue transmitting data down the stack.
 *  Takes the termios rwsem to protect against parallel throttle/unthrottle
 *  and also to ensure the driver can consistently reference its own
 *  termios data at this point when implementing software flow control.
 *
 *  Drivers should however remember that the stack can issue a throttle,
 *  then change flow control method, then unthrottle.
 */

void tty_unthrottle(struct tty_struct *tty)
{
    down_write(&tty->termios_rwsem);
    if (test_and_clear_bit(TTY_THROTTLED, &tty->flags) &&
        tty->ops->unthrottle)
        tty->ops->unthrottle(tty);
    tty->flow_change = 0;
    up_write(&tty->termios_rwsem);
}
EXPORT_SYMBOL(tty_unthrottle);
