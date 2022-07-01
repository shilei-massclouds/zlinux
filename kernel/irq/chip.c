// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the core interrupt handling code, for irq-chip based
 * architectures. Detailed information is available in
 * Documentation/core-api/genericirq.rst
 */

#include <linux/irq.h>
#include <linux/module.h>
#if 0
#include <linux/msi.h>
#endif
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/irqdomain.h>

#include "internals.h"

enum {
    IRQ_STARTUP_NORMAL,
    IRQ_STARTUP_MANAGED,
    IRQ_STARTUP_ABORT,
};

static irqreturn_t bad_chained_irq(int irq, void *dev_id)
{
    WARN_ONCE(1, "Chained irq %d should not call an action\n", irq);
    return IRQ_NONE;
}

static void irq_state_clr_masked(struct irq_desc *desc)
{
    irqd_clear(&desc->irq_data, IRQD_IRQ_MASKED);
}

static void irq_state_set_started(struct irq_desc *desc)
{
    irqd_set(&desc->irq_data, IRQD_IRQ_STARTED);
}

static void irq_state_clr_disabled(struct irq_desc *desc)
{
    irqd_clear(&desc->irq_data, IRQD_IRQ_DISABLED);
}

/*
 * Chained handlers should never call action on their IRQ. This default
 * action will emit warning if such thing happens.
 */
struct irqaction chained_action = {
    .handler = bad_chained_irq,
};

static int __irq_startup(struct irq_desc *desc)
{
    struct irq_data *d = irq_desc_get_irq_data(desc);
    int ret = 0;

    /* Warn if this interrupt is not activated but try nevertheless */
    WARN_ON_ONCE(!irqd_is_activated(d));

    if (d->chip->irq_startup) {
        ret = d->chip->irq_startup(d);
        irq_state_clr_disabled(desc);
        irq_state_clr_masked(desc);
    } else {
        irq_enable(desc);
    }
    irq_state_set_started(desc);
    return ret;
}

struct irq_data *irq_get_irq_data(unsigned int irq)
{
    struct irq_desc *desc = irq_to_desc(irq);

    return desc ? &desc->irq_data : NULL;
}
EXPORT_SYMBOL_GPL(irq_get_irq_data);

void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set)
{
    unsigned long flags, trigger, tmp;
    struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

    if (!desc)
        return;

    /*
     * Warn when a driver sets the no autoenable flag on an already
     * active interrupt.
     */
    WARN_ON_ONCE(!desc->depth && (set & _IRQ_NOAUTOEN));

    irq_settings_clr_and_set(desc, clr, set);

    trigger = irqd_get_trigger_type(&desc->irq_data);

    irqd_clear(&desc->irq_data,
               IRQD_NO_BALANCING | IRQD_PER_CPU |
               IRQD_TRIGGER_MASK | IRQD_LEVEL | IRQD_MOVE_PCNTXT);

    if (irq_settings_has_no_balance_set(desc))
        irqd_set(&desc->irq_data, IRQD_NO_BALANCING);
    if (irq_settings_is_per_cpu(desc))
        irqd_set(&desc->irq_data, IRQD_PER_CPU);
    if (irq_settings_can_move_pcntxt(desc))
        irqd_set(&desc->irq_data, IRQD_MOVE_PCNTXT);
    if (irq_settings_is_level(desc))
        irqd_set(&desc->irq_data, IRQD_LEVEL);

    tmp = irq_settings_get_trigger_mask(desc);
    if (tmp != IRQ_TYPE_NONE)
        trigger = tmp;

    irqd_set(&desc->irq_data, trigger);

    irq_put_desc_unlock(desc, flags);
}

/**
 * handle_percpu_devid_irq - Per CPU local irq handler with per cpu dev ids
 * @desc:   the interrupt description structure for this irq
 *
 * Per CPU interrupts on SMP machines without locking requirements. Same as
 * handle_percpu_irq() above but with the following extras:
 *
 * action->percpu_dev_id is a pointer to percpu variables which
 * contain the real device id for the cpu on which this handler is
 * called
 */
void handle_percpu_devid_irq(struct irq_desc *desc)
{
    struct irq_chip *chip = irq_desc_get_chip(desc);
    struct irqaction *action = desc->action;
    unsigned int irq = irq_desc_get_irq(desc);
    irqreturn_t res;

    panic("%s: END!\n", __func__);
#if 0
    /*
     * PER CPU interrupts are not serialized. Do not touch
     * desc->tot_count.
     */
    __kstat_incr_irqs_this_cpu(desc);

    if (chip->irq_ack)
        chip->irq_ack(&desc->irq_data);

    if (likely(action)) {
        trace_irq_handler_entry(irq, action);
        res = action->handler(irq, raw_cpu_ptr(action->percpu_dev_id));
        trace_irq_handler_exit(irq, action, res);
    } else {
        unsigned int cpu = smp_processor_id();
        bool enabled = cpumask_test_cpu(cpu, desc->percpu_enabled);

        if (enabled)
            irq_percpu_disable(desc, cpu);

        pr_err_once("Spurious%s percpu IRQ%u on CPU%u\n",
                enabled ? " and unmasked" : "", irq, cpu);
    }

    if (chip->irq_eoi)
        chip->irq_eoi(&desc->irq_data);
#endif
}

int irq_activate(struct irq_desc *desc)
{
    struct irq_data *d = irq_desc_get_irq_data(desc);

    if (!irqd_affinity_is_managed(d))
        return irq_domain_activate_irq(d, false);
    return 0;
}

int irq_activate_and_startup(struct irq_desc *desc, bool resend)
{
    if (WARN_ON(irq_activate(desc)))
        return 0;
    return irq_startup(desc, resend, IRQ_START_FORCE);
}

static void
__irq_do_set_handler(struct irq_desc *desc, irq_flow_handler_t handle,
                     int is_chained, const char *name)
{
    if (!handle) {
        handle = handle_bad_irq;
    } else {
        struct irq_data *irq_data = &desc->irq_data;
        /*
         * With hierarchical domains we might run into a
         * situation where the outermost chip is not yet set
         * up, but the inner chips are there.  Instead of
         * bailing we install the handler, but obviously we
         * cannot enable/startup the interrupt at this point.
         */
        while (irq_data) {
            if (irq_data->chip != &no_irq_chip)
                break;
            /*
             * Bail out if the outer chip is not set up
             * and the interrupt supposed to be started
             * right away.
             */
            if (WARN_ON(is_chained))
                return;
            /* Try the parent */
            irq_data = irq_data->parent_data;
        }
        if (WARN_ON(!irq_data || irq_data->chip == &no_irq_chip))
            return;
    }

    /* Uninstall? */
    if (handle == handle_bad_irq) {
        if (desc->irq_data.chip != &no_irq_chip)
            mask_ack_irq(desc);
        irq_state_set_disabled(desc);
        if (is_chained)
            desc->action = NULL;
        desc->depth = 1;
    }
    desc->handle_irq = handle;
    desc->name = name;

    if (handle != handle_bad_irq && is_chained) {
        unsigned int type = irqd_get_trigger_type(&desc->irq_data);

        /*
         * We're about to start this interrupt immediately,
         * hence the need to set the trigger configuration.
         * But the .set_type callback may have overridden the
         * flow handler, ignoring that we're dealing with a
         * chained interrupt. Reset it immediately because we
         * do know better.
         */
        if (type != IRQ_TYPE_NONE) {
            __irq_set_trigger(desc, type);
            desc->handle_irq = handle;
        }

        irq_settings_set_noprobe(desc);
        irq_settings_set_norequest(desc);
        irq_settings_set_nothread(desc);
        desc->action = &chained_action;
        irq_activate_and_startup(desc, IRQ_RESEND);
    }
}

void
__irq_set_handler(unsigned int irq, irq_flow_handler_t handle,
                  int is_chained, const char *name)
{
    unsigned long flags;
    struct irq_desc *desc = irq_get_desc_buslock(irq, &flags, 0);

    if (!desc)
        return;

    __irq_do_set_handler(desc, handle, is_chained, name);
    irq_put_desc_busunlock(desc, flags);
}
EXPORT_SYMBOL_GPL(__irq_set_handler);

void mask_irq(struct irq_desc *desc)
{
    if (irqd_irq_masked(&desc->irq_data))
        return;

    if (desc->irq_data.chip->irq_mask) {
        desc->irq_data.chip->irq_mask(&desc->irq_data);
        irq_state_set_masked(desc);
    }
}

void unmask_irq(struct irq_desc *desc)
{
    if (!irqd_irq_masked(&desc->irq_data))
        return;

    if (desc->irq_data.chip->irq_unmask) {
        desc->irq_data.chip->irq_unmask(&desc->irq_data);
        irq_state_clr_masked(desc);
    }
}

static int
__irq_startup_managed(struct irq_desc *desc, struct cpumask *aff, bool force)
{
    struct irq_data *d = irq_desc_get_irq_data(desc);

    if (!irqd_affinity_is_managed(d))
        return IRQ_STARTUP_NORMAL;

    irqd_clr_managed_shutdown(d);

    if (cpumask_any_and(aff, cpu_online_mask) >= nr_cpu_ids) {
        /*
         * Catch code which fiddles with enable_irq() on a managed
         * and potentially shutdown IRQ. Chained interrupt
         * installment or irq auto probing should not happen on
         * managed irqs either.
         */
        if (WARN_ON_ONCE(force))
            return IRQ_STARTUP_ABORT;
        /*
         * The interrupt was requested, but there is no online CPU
         * in it's affinity mask. Put it into managed shutdown
         * state and let the cpu hotplug mechanism start it up once
         * a CPU in the mask becomes available.
         */
        return IRQ_STARTUP_ABORT;
    }
    /*
     * Managed interrupts have reserved resources, so this should not
     * happen.
     */
    if (WARN_ON(irq_domain_activate_irq(d, false)))
        return IRQ_STARTUP_ABORT;
    return IRQ_STARTUP_MANAGED;
}

int irq_startup(struct irq_desc *desc, bool resend, bool force)
{
    struct irq_data *d = irq_desc_get_irq_data(desc);
    struct cpumask *aff = irq_data_get_affinity_mask(d);
    int ret = 0;

    desc->depth = 0;

    if (irqd_is_started(d)) {
        irq_enable(desc);
    } else {
        switch (__irq_startup_managed(desc, aff, force)) {
        case IRQ_STARTUP_NORMAL:
            if (d->chip->flags & IRQCHIP_AFFINITY_PRE_STARTUP)
                irq_setup_affinity(desc);
            ret = __irq_startup(desc);
            if (!(d->chip->flags & IRQCHIP_AFFINITY_PRE_STARTUP))
                irq_setup_affinity(desc);
            break;
        case IRQ_STARTUP_MANAGED:
            irq_do_set_affinity(d, aff, false);
            ret = __irq_startup(desc);
            break;
        case IRQ_STARTUP_ABORT:
            irqd_set_managed_shutdown(d);
            return 0;
        }
    }
    if (resend)
        check_irq_resend(desc, false);

    return ret;
}

void irq_enable(struct irq_desc *desc)
{
    if (!irqd_irq_disabled(&desc->irq_data)) {
        unmask_irq(desc);
    } else {
        irq_state_clr_disabled(desc);
        if (desc->irq_data.chip->irq_enable) {
            desc->irq_data.chip->irq_enable(&desc->irq_data);
            irq_state_clr_masked(desc);
        } else {
            unmask_irq(desc);
        }
    }
}

/**
 *  irq_set_handler_data - set irq handler data for an irq
 *  @irq:   Interrupt number
 *  @data:  Pointer to interrupt specific data
 *
 *  Set the hardware irq controller data for an irq
 */
int irq_set_handler_data(unsigned int irq, void *data)
{
    unsigned long flags;
    struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);

    if (!desc)
        return -EINVAL;
    desc->irq_common_data.handler_data = data;
    irq_put_desc_unlock(desc, flags);
    return 0;
}
EXPORT_SYMBOL(irq_set_handler_data);
