// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>
//#include <linux/tty_flip.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
//#include <linux/kd.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/vt_kern.h>
//#include <linux/selection.h>
//#include <linux/tiocl.h>
//#include <linux/kbd_kern.h>
//#include <linux/consolemap.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/pm.h>
//#include <linux/font.h>
#include <linux/bitops.h>
//#include <linux/notifier.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/uaccess.h>
//#include <linux/kdb.h>
#include <linux/ctype.h>
#include <linux/bsearch.h>
//#include <linux/gcd.h>

/*
 * fg_console is the current virtual console,
 * last_console is the last used one,
 * want_console is the console we want to switch to,
 * saved_* variants are for save/restore around kernel debugger enter/leave
 */
int fg_console;
int last_console;
int want_console = -1;
static int saved_fg_console;
static int saved_last_console;
static int saved_want_console;
static int saved_vc_mode;
static int saved_console_blanked;

struct tty_driver *console_driver;
