// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/termios.h>
#include <linux/tty.h>
#include <linux/export.h>
#include "tty.h"

/**
 *  tty_termios_encode_baud_rate
 *  @termios: ktermios structure holding user requested state
 *  @ibaud: input speed
 *  @obaud: output speed
 *
 *  Encode the speeds set into the passed termios structure. This is
 *  used as a library helper for drivers so that they can report back
 *  the actual speed selected when it differs from the speed requested
 *
 *  For maximal back compatibility with legacy SYS5/POSIX *nix behaviour
 *  we need to carefully set the bits when the user does not get the
 *  desired speed. We allow small margins and preserve as much of possible
 *  of the input intent to keep compatibility.
 *
 *  Locking: Caller should hold termios lock. This is already held
 *  when calling this function from the driver termios handler.
 *
 *  The ifdefs deal with platforms whose owners have yet to update them
 *  and will all go away once this is done.
 */
void tty_termios_encode_baud_rate(struct ktermios *termios,
                                  speed_t ibaud, speed_t obaud)
{
    panic("%s: END!\n", __func__);
}
