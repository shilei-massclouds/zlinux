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
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

#include <asm/irq_regs.h>

#include "internals.h"

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

static void warn_no_thread(unsigned int irq, struct irqaction *action)
{
    if (test_and_set_bit(IRQTF_WARNED, &action->thread_flags))
        return;

    printk(KERN_WARNING "IRQ %d device %s returned IRQ_WAKE_THREAD "
           "but no thread function available.", irq, action->name);
}

void __irq_wake_thread(struct irq_desc *desc, struct irqaction *action)
{
    /*
     * In case the thread crashed and was killed we just pretend that
     * we handled the interrupt. The hardirq handler has disabled the
     * device interrupt, so no irq storm is lurking.
     */
    if (action->thread->flags & PF_EXITING)
        return;

    /*
     * Wake up the handler thread for this action. If the
     * RUNTHREAD bit is already set, nothing to do.
     */
    if (test_and_set_bit(IRQTF_RUNTHREAD, &action->thread_flags))
        return;

    panic("%s: END!\n", __func__);
}

irqreturn_t __handle_irq_event_percpu(struct irq_desc *desc)
{
    irqreturn_t retval = IRQ_NONE;
    unsigned int irq = desc->irq_data.irq;
    struct irqaction *action;

    for_each_action_of_desc(desc, action) {
        irqreturn_t res;

        res = action->handler(irq, action->dev_id);

        if (WARN_ONCE(!irqs_disabled(),
                      "irq %u handler %pS enabled interrupts\n",
                      irq, action->handler))
            local_irq_disable();

        switch (res) {
        case IRQ_WAKE_THREAD:
            /*
             * Catch drivers which return WAKE_THREAD but
             * did not set up a thread function
             */
            if (unlikely(!action->thread_fn)) {
                warn_no_thread(irq, action);
                break;
            }

            __irq_wake_thread(desc, action);
            break;

        default:
            break;
        }

        retval |= res;
    }

    return retval;
}

irqreturn_t handle_irq_event_percpu(struct irq_desc *desc)
{
    irqreturn_t retval;

    retval = __handle_irq_event_percpu(desc);

#if 0
    add_interrupt_randomness(desc->irq_data.irq);
#endif

#if 0
    if (!irq_settings_no_debug(desc))
        note_interrupt(desc, retval);
#endif
    return retval;
}

irqreturn_t handle_irq_event(struct irq_desc *desc)
{
    irqreturn_t ret;

    desc->istate &= ~IRQS_PENDING;
    irqd_set(&desc->irq_data, IRQD_IRQ_INPROGRESS);
    raw_spin_unlock(&desc->lock);

    ret = handle_irq_event_percpu(desc);

    raw_spin_lock(&desc->lock);
    irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);
    return ret;
}
