// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2004 Linus Torvalds, Ingo Molnar
 *
 * This file contains spurious interrupt handling.
 */

#include <linux/jiffies.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#if 0
#include <linux/timer.h>
#endif

#include "internals.h"

bool noirqdebug __read_mostly;
