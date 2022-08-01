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

/**
 * generic_handle_arch_irq - root irq handler for architectures which do no
 *                           entry accounting themselves
 * @regs:   Register file coming from the low-level handling code
 */
asmlinkage void noinstr generic_handle_arch_irq(struct pt_regs *regs)
{
    struct pt_regs *old_regs;

    panic("%s: END!\n", __func__);
    //irq_enter();
    old_regs = set_irq_regs(regs);
    handle_arch_irq(regs);
    set_irq_regs(old_regs);
    //irq_exit();
}

/**
 * handle_bad_irq - handle spurious and unhandled irqs
 * @desc:      description of the interrupt
 *
 * Handles spurious and unhandled IRQ's. It also prints a debugmessage.
 */
void handle_bad_irq(struct irq_desc *desc)
{
    panic("%s: END!\n", __func__);
#if 0
    unsigned int irq = irq_desc_get_irq(desc);

    print_irq_desc(irq, desc);
    kstat_incr_irqs_this_cpu(desc);
    ack_bad_irq(irq);
#endif
}
EXPORT_SYMBOL_GPL(handle_bad_irq);

