// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006 Thomas Gleixner
 *
 * This file contains driver APIs to the irq subsystem.
 */

#define pr_fmt(fmt) "genirq: " fmt

#include <linux/irq.h>
#include <linux/kthread.h>
#include <linux/module.h>
#if 0
#include <linux/random.h>
#endif
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#if 0
#include <linux/sched/isolation.h>
#include <uapi/linux/sched/types.h>
#include <linux/task_work.h>
#endif

#include "internals.h"

cpumask_var_t irq_default_affinity;

static bool __irq_can_set_affinity(struct irq_desc *desc)
{
    if (!desc || !irqd_can_balance(&desc->irq_data) ||
        !desc->irq_data.chip || !desc->irq_data.chip->irq_set_affinity)
        return false;
    return true;
}

int __irq_set_trigger(struct irq_desc *desc, unsigned long flags)
{
    struct irq_chip *chip = desc->irq_data.chip;
    int ret, unmask = 0;

    if (!chip || !chip->irq_set_type) {
        /*
         * IRQF_TRIGGER_* but the PIC does not support multiple
         * flow-types?
         */
        pr_debug("No set_type function for IRQ %d (%s)\n",
             irq_desc_get_irq(desc),
             chip ? (chip->name ? : "unknown") : "unknown");
        return 0;
    }

    if (chip->flags & IRQCHIP_SET_TYPE_MASKED) {
        if (!irqd_irq_masked(&desc->irq_data))
            mask_irq(desc);
        if (!irqd_irq_disabled(&desc->irq_data))
            unmask = 1;
    }

    /* Mask all flags except trigger mode */
    flags &= IRQ_TYPE_SENSE_MASK;
    ret = chip->irq_set_type(&desc->irq_data, flags);

    switch (ret) {
    case IRQ_SET_MASK_OK:
    case IRQ_SET_MASK_OK_DONE:
        irqd_clear(&desc->irq_data, IRQD_TRIGGER_MASK);
        irqd_set(&desc->irq_data, flags);
        fallthrough;

    case IRQ_SET_MASK_OK_NOCOPY:
        flags = irqd_get_trigger_type(&desc->irq_data);
        irq_settings_set_trigger_mask(desc, flags);
        irqd_clear(&desc->irq_data, IRQD_LEVEL);
        irq_settings_clr_level(desc);
        if (flags & IRQ_TYPE_LEVEL_MASK) {
            irq_settings_set_level(desc);
            irqd_set(&desc->irq_data, IRQD_LEVEL);
        }

        ret = 0;
        break;
    default:
        pr_err("Setting trigger mode %lu for irq %u failed (%pS)\n",
               flags, irq_desc_get_irq(desc), chip->irq_set_type);
    }
    if (unmask)
        unmask_irq(desc);
    return ret;
}

/*
 * Generic version of the affinity autoselector.
 */
int irq_setup_affinity(struct irq_desc *desc)
{
    struct cpumask *set = irq_default_affinity;
    int ret, node = irq_desc_get_node(desc);
    static DEFINE_RAW_SPINLOCK(mask_lock);
    static struct cpumask mask;

    /* Excludes PER_CPU and NO_BALANCE interrupts */
    if (!__irq_can_set_affinity(desc))
        return 0;

}

int irq_do_set_affinity(struct irq_data *data,
                        const struct cpumask *mask, bool force)
{
    struct irq_desc *desc = irq_data_to_desc(data);
    struct irq_chip *chip = irq_data_get_irq_chip(data);
    int ret;

    if (!chip || !chip->irq_set_affinity)
        return -EINVAL;

    panic("%s: END!\n", __func__);
}

static bool
irq_set_affinity_deactivated(struct irq_data *data,
                             const struct cpumask *mask, bool force)
{
    struct irq_desc *desc = irq_data_to_desc(data);

    /*
     * Handle irq chips which can handle affinity only in activated
     * state correctly
     *
     * If the interrupt is not yet activated, just store the affinity
     * mask and do not call the chip driver at all. On activation the
     * driver has to make sure anyway that the interrupt is in a
     * usable state so startup works.
     */
    if (irqd_is_activated(data) || !irqd_affinity_on_activate(data))
        return false;

    cpumask_copy(desc->irq_common_data.affinity, mask);
    irqd_set(data, IRQD_AFFINITY_SET);
    return true;
}

int irq_set_affinity_locked(struct irq_data *data, const struct cpumask *mask,
                            bool force)
{
    struct irq_chip *chip = irq_data_get_irq_chip(data);
    struct irq_desc *desc = irq_data_to_desc(data);
    int ret = 0;

    if (!chip || !chip->irq_set_affinity)
        return -EINVAL;

    if (irq_set_affinity_deactivated(data, mask, force))
        return 0;

    pr_warn("%s: NO implementation!\n", __func__);

    return 0;
}

static int __irq_set_affinity(unsigned int irq, const struct cpumask *mask,
                              bool force)
{
    struct irq_desc *desc = irq_to_desc(irq);
    unsigned long flags;
    int ret;

    if (!desc)
        return -EINVAL;

    raw_spin_lock_irqsave(&desc->lock, flags);
    ret = irq_set_affinity_locked(irq_desc_get_irq_data(desc), mask, force);
    raw_spin_unlock_irqrestore(&desc->lock, flags);
    return ret;
}

/**
 * irq_set_affinity - Set the irq affinity of a given irq
 * @irq:    Interrupt to set affinity
 * @cpumask:    cpumask
 *
 * Fails if cpumask does not contain an online CPU
 */
int irq_set_affinity(unsigned int irq, const struct cpumask *cpumask)
{
    return __irq_set_affinity(irq, cpumask, false);
}
EXPORT_SYMBOL_GPL(irq_set_affinity);
