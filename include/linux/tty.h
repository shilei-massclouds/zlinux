/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TTY_H
#define _LINUX_TTY_H

#include <linux/fs.h>
#include <linux/major.h>
//#include <linux/termios.h>
#include <linux/workqueue.h>
#include <linux/tty_buffer.h>
#include <linux/tty_driver.h>
#if 0
#include <linux/tty_ldisc.h>
#endif
#include <linux/tty_port.h>
#include <linux/mutex.h>
#include <linux/tty_flags.h>
//#include <uapi/linux/tty.h>
#include <linux/rwsem.h>
#include <linux/llist.h>

extern struct ktermios tty_std_termios;

#endif /* _LINUX_TTY_H */
