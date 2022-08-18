// SPDX-License-Identifier: GPL-2.0
/* calibrate.c: default delay calibration
 *
 * Excised from init/main.c
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/init.h>
//#include <linux/timex.h>
#include <linux/smp.h>
#include <linux/percpu.h>

unsigned long lpj_fine;
unsigned long preset_lpj;
