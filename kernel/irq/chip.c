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

    /*
     * PER CPU interrupts are not serialized. Do not touch
     * desc->tot_count.
     */
    __kstat_incr_irqs_this_cpu(desc);

    if (chip->irq_ack)
        chip->irq_ack(&desc->irq_data);

    if (likely(action)) {
        res = action->handler(irq, raw_cpu_ptr(action->percpu_dev_id));
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
        printk("+++++++++++++++ %s: %s\n", __func__, desc->irq_data.chip->name);
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

/**
 * irq_chip_retrigger_hierarchy - Retrigger an interrupt in hardware
 * @data:   Pointer to interrupt specific data
 *
 * Iterate through the domain hierarchy of the interrupt and check
 * whether a hw retrigger function exists. If yes, invoke it.
 */
int irq_chip_retrigger_hierarchy(struct irq_data *data)
{
    for (data = data->parent_data; data; data = data->parent_data)
        if (data->chip && data->chip->irq_retrigger)
            return data->chip->irq_retrigger(data);

    return 0;
}
EXPORT_SYMBOL_GPL(irq_chip_retrigger_hierarchy);

static bool irq_check_poll(struct irq_desc *desc)
{
    if (!(desc->istate & IRQS_POLL_INPROGRESS))
        return false;
    //return irq_wait_for_poll(desc);
    panic("%s: END!\n", __func__);
}

static bool irq_may_run(struct irq_desc *desc)
{
    unsigned int mask = IRQD_IRQ_INPROGRESS | IRQD_WAKEUP_ARMED;

    /*
     * If the interrupt is not in progress and is not an armed
     * wakeup interrupt, proceed.
     */
    if (!irqd_has_set(&desc->irq_data, mask))
        return true;

    /*
     * Handle a potential concurrent poll on a different core.
     */
    return irq_check_poll(desc);
}

static void cond_unmask_eoi_irq(struct irq_desc *desc, struct irq_chip *chip)
{
    if (!(desc->istate & IRQS_ONESHOT)) {
        chip->irq_eoi(&desc->irq_data);
        return;
    }
    /*
     * We need to unmask in the following cases:
     * - Oneshot irq which did not wake the thread (caused by a
     *   spurious interrupt or a primary handler handling it
     *   completely).
     */
    if (!irqd_irq_disabled(&desc->irq_data) &&
        irqd_irq_masked(&desc->irq_data) && !desc->threads_oneshot) {
        chip->irq_eoi(&desc->irq_data);
        unmask_irq(desc);
    } else if (!(chip->flags & IRQCHIP_EOI_THREADED)) {
        chip->irq_eoi(&desc->irq_data);
    }
}

/**
 *  handle_fasteoi_irq - irq handler for transparent controllers
 *  @desc:  the interrupt description structure for this irq
 *
 *  Only a single callback will be issued to the chip: an ->eoi()
 *  call when the interrupt has been serviced. This enables support
 *  for modern forms of interrupt handlers, which handle the flow
 *  details in hardware, transparently.
 */
void handle_fasteoi_irq(struct irq_desc *desc)
{
    struct irq_chip *chip = desc->irq_data.chip;

    raw_spin_lock(&desc->lock);

    if (!irq_may_run(desc))
        goto out;

    desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);

    /*
     * If its disabled or no action available
     * then mask it and get out of here:
     */
    if (unlikely(!desc->action || irqd_irq_disabled(&desc->irq_data))) {
        desc->istate |= IRQS_PENDING;
        mask_irq(desc);
        goto out;
    }

    kstat_incr_irqs_this_cpu(desc);
    if (desc->istate & IRQS_ONESHOT)
        mask_irq(desc);

    handle_irq_event(desc);

    cond_unmask_eoi_irq(desc, chip);

    raw_spin_unlock(&desc->lock);
    return;

 out:
    if (!(chip->flags & IRQCHIP_EOI_IF_HANDLED))
        chip->irq_eoi(&desc->irq_data);
    raw_spin_unlock(&desc->lock);
}
EXPORT_SYMBOL_GPL(handle_fasteoi_irq);

void irq_percpu_enable(struct irq_desc *desc, unsigned int cpu)
{
    if (desc->irq_data.chip->irq_enable)
        desc->irq_data.chip->irq_enable(&desc->irq_data);
    else
        desc->irq_data.chip->irq_unmask(&desc->irq_data);
    cpumask_set_cpu(cpu, desc->percpu_enabled);
}

void irq_percpu_disable(struct irq_desc *desc, unsigned int cpu)
{
    if (desc->irq_data.chip->irq_disable)
        desc->irq_data.chip->irq_disable(&desc->irq_data);
    else
        desc->irq_data.chip->irq_mask(&desc->irq_data);
    cpumask_clear_cpu(cpu, desc->percpu_enabled);
}

static void __irq_disable(struct irq_desc *desc, bool mask)
{
    if (irqd_irq_disabled(&desc->irq_data)) {
        if (mask)
            mask_irq(desc);
    } else {
        irq_state_set_disabled(desc);
        if (desc->irq_data.chip->irq_disable) {
            desc->irq_data.chip->irq_disable(&desc->irq_data);
            irq_state_set_masked(desc);
        } else if (mask) {
            mask_irq(desc);
        }
    }
}

/**
 * irq_disable - Mark interrupt disabled
 * @desc:   irq descriptor which should be disabled
 *
 * If the chip does not implement the irq_disable callback, we
 * use a lazy disable approach. That means we mark the interrupt
 * disabled, but leave the hardware unmasked. That's an
 * optimization because we avoid the hardware access for the
 * common case where no interrupt happens after we marked it
 * disabled. If an interrupt happens, then the interrupt flow
 * handler masks the line at the hardware level and marks it
 * pending.
 *
 * If the interrupt chip does not implement the irq_disable callback,
 * a driver can disable the lazy approach for a particular irq line by
 * calling 'irq_set_status_flags(irq, IRQ_DISABLE_UNLAZY)'. This can
 * be used for devices which cannot disable the interrupt at the
 * device level under certain circumstances and have to use
 * disable_irq[_nosync] instead.
 */
void irq_disable(struct irq_desc *desc)
{
    __irq_disable(desc, irq_settings_disable_unlazy(desc));
}
