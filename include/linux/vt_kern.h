/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _VT_KERN_H
#define _VT_KERN_H

/*
 * this really is an extension of the vc_cons structure in console.c, but
 * with information needed by the vt package
 */

#if 0
#include <linux/vt.h>
#include <linux/kd.h>
#endif
#include <linux/tty.h>
#include <linux/mutex.h>
//#include <linux/console_struct.h>
#include <linux/mm.h>
#if 0
#include <linux/consolemap.h>
#include <linux/notifier.h>
#endif

void kd_mksound(unsigned int hz, unsigned int ticks);
int kbd_rate(struct kbd_repeat *rep);

extern int fg_console, last_console, want_console;

#endif /* _VT_KERN_H */
