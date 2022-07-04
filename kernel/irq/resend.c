// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner
 *
 * This file contains the IRQ-resend code
 *
 * If the interrupt is waiting to be processed, we try to re-run it.
 * We can't directly run it from here since the caller might be in an
 * interrupt-protected region. Not all irq controller chips can
 * retrigger interrupts at the hardware level, so in those cases
 * we allow the resending of IRQs via a tasklet.
 */

#include <linux/irq.h>
#include <linux/module.h>
#if 0
#include <linux/random.h>
#endif
#include <linux/interrupt.h>

#include "internals.h"

static int irq_sw_resend(struct irq_desc *desc)
{
    return -EINVAL;
}

static int try_retrigger(struct irq_desc *desc)
{
    if (desc->irq_data.chip->irq_retrigger)
        return desc->irq_data.chip->irq_retrigger(&desc->irq_data);

    return irq_chip_retrigger_hierarchy(&desc->irq_data);
}

/*
 * IRQ resend
 *
 * Is called with interrupts disabled and desc->lock held.
 */
int check_irq_resend(struct irq_desc *desc, bool inject)
{
    int err = 0;

    /*
     * We do not resend level type interrupts. Level type interrupts
     * are resent by hardware when they are still active. Clear the
     * pending bit so suspend/resume does not get confused.
     */
    if (irq_settings_is_level(desc)) {
        desc->istate &= ~IRQS_PENDING;
        return -EINVAL;
    }

    if (desc->istate & IRQS_REPLAY)
        return -EBUSY;

    if (!(desc->istate & IRQS_PENDING) && !inject)
        return 0;

    desc->istate &= ~IRQS_PENDING;

    if (!try_retrigger(desc))
        err = irq_sw_resend(desc);

    /* If the retrigger was successful, mark it with the REPLAY bit */
    if (!err)
        desc->istate |= IRQS_REPLAY;
    return err;
}
