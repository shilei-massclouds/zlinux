// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the core interrupt handling code. Detailed
 * information is available in Documentation/core-api/genericirq.rst
 *
 */

#include <linux/irq.h>
#if 0
#include <linux/random.h>
#endif
#include <linux/sched.h>
#if 0
#include <linux/interrupt.h>
#endif
#include <linux/kernel_stat.h>

#include <asm/irq_regs.h>

#if 0
#include "internals.h"
#endif

void (*handle_arch_irq)(struct pt_regs *) __ro_after_init;

int __init set_handle_irq(void (*handle_irq)(struct pt_regs *))
{
    if (handle_arch_irq)
        return -EBUSY;

    handle_arch_irq = handle_irq;
    return 0;
}
