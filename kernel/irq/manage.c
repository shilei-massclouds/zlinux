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
#include <linux/sched/isolation.h>
#if 0
#include <uapi/linux/sched/types.h>
#include <linux/task_work.h>
#endif

#include "internals.h"

DEFINE_STATIC_KEY_FALSE(force_irqthreads_key);

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

    raw_spin_lock(&mask_lock);
    /*
     * Preserve the managed affinity setting and a userspace affinity
     * setup, but make sure that one of the targets is online.
     */
    if (irqd_affinity_is_managed(&desc->irq_data) ||
        irqd_has_set(&desc->irq_data, IRQD_AFFINITY_SET)) {
        if (cpumask_intersects(desc->irq_common_data.affinity,
                               cpu_online_mask))
            set = desc->irq_common_data.affinity;
        else
            irqd_clear(&desc->irq_data, IRQD_AFFINITY_SET);
    }

    cpumask_and(&mask, cpu_online_mask, set);
    if (cpumask_empty(&mask))
        cpumask_copy(&mask, cpu_online_mask);

    if (node != NUMA_NO_NODE) {
        const struct cpumask *nodemask = cpumask_of_node(node);

        /* make sure at least one of the cpus in nodemask is online */
        if (cpumask_intersects(&mask, nodemask))
            cpumask_and(&mask, &mask, nodemask);
    }

    ret = irq_do_set_affinity(&desc->irq_data, &mask, false);
    raw_spin_unlock(&mask_lock);
    return ret;
}

/**
 *  irq_set_thread_affinity - Notify irq threads to adjust affinity
 *  @desc:      irq descriptor which has affinity changed
 *
 *  We just set IRQTF_AFFINITY and delegate the affinity setting
 *  to the interrupt thread itself. We can not call
 *  set_cpus_allowed_ptr() here as we hold desc->lock and this
 *  code can be called from hard interrupt context.
 */
void irq_set_thread_affinity(struct irq_desc *desc)
{
    struct irqaction *action;

    for_each_action_of_desc(desc, action)
        if (action->thread)
            set_bit(IRQTF_AFFINITY, &action->thread_flags);
}

int irq_do_set_affinity(struct irq_data *data,
                        const struct cpumask *mask, bool force)
{
    struct irq_desc *desc = irq_data_to_desc(data);
    struct irq_chip *chip = irq_data_get_irq_chip(data);
    int ret;

    if (!chip || !chip->irq_set_affinity)
        return -EINVAL;

    /*
     * If this is a managed interrupt and housekeeping is enabled on
     * it check whether the requested affinity mask intersects with
     * a housekeeping CPU. If so, then remove the isolated CPUs from
     * the mask and just keep the housekeeping CPU(s). This prevents
     * the affinity setter from routing the interrupt to an isolated
     * CPU to avoid that I/O submitted from a housekeeping CPU causes
     * interrupts on an isolated one.
     *
     * If the masks do not intersect or include online CPU(s) then
     * keep the requested mask. The isolated target CPUs are only
     * receiving interrupts when the I/O operation was submitted
     * directly from them.
     *
     * If all housekeeping CPUs in the affinity mask are offline, the
     * interrupt will be migrated by the CPU hotplug code once a
     * housekeeping CPU which belongs to the affinity mask comes
     * online.
     */
    if (irqd_affinity_is_managed(data) &&
        housekeeping_enabled(HK_TYPE_MANAGED_IRQ)) {
        panic("%s: HK_TYPE_MANAGED_IRQ!\n", __func__);
    } else {
        ret = chip->irq_set_affinity(data, mask, force);
    }

    switch (ret) {
    case IRQ_SET_MASK_OK:
    case IRQ_SET_MASK_OK_DONE:
        cpumask_copy(desc->irq_common_data.affinity, mask);
        fallthrough;
    case IRQ_SET_MASK_OK_NOCOPY:
        irq_set_thread_affinity(desc);
        ret = 0;
    }

    return ret;
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

static inline int irq_set_affinity_pending(struct irq_data *data,
                                           const struct cpumask *dest)
{
    return -EBUSY;
}

static int irq_try_set_affinity(struct irq_data *data,
                                const struct cpumask *dest, bool force)
{
    int ret = irq_do_set_affinity(data, dest, force);

    /*
     * In case that the underlying vector management is busy and the
     * architecture supports the generic pending mechanism then utilize
     * this to avoid returning an error to user space.
     */
    if (ret == -EBUSY && !force)
        ret = irq_set_affinity_pending(data, dest);
    return ret;
}

int irq_set_affinity_locked(struct irq_data *data,
                            const struct cpumask *mask,
                            bool force)
{
    struct irq_chip *chip = irq_data_get_irq_chip(data);
    struct irq_desc *desc = irq_data_to_desc(data);
    int ret = 0;

    if (!chip || !chip->irq_set_affinity)
        return -EINVAL;

    if (irq_set_affinity_deactivated(data, mask, force))
        return 0;

    if (!irqd_is_setaffinity_pending(data)) {
        ret = irq_try_set_affinity(data, mask, force);
    } else {
        panic("%s: ELSE!\n", __func__);
#if 0
        irqd_set_move_pending(data);
        irq_copy_pending(desc, mask);
#endif
    }

#if 0
    if (desc->affinity_notify) {
        kref_get(&desc->affinity_notify->kref);
        if (!schedule_work(&desc->affinity_notify->work)) {
            /* Work was already scheduled, drop our extra ref */
            kref_put(&desc->affinity_notify->kref,
                     desc->affinity_notify->release);
        }
    }
#endif
    irqd_set(data, IRQD_AFFINITY_SET);

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

/*
 * Default primary interrupt handler for threaded interrupts. Is
 * assigned as primary handler when request_threaded_irq is called
 * with handler == NULL. Useful for oneshot interrupts.
 */
static irqreturn_t irq_default_primary_handler(int irq, void *dev_id)
{
    return IRQ_WAKE_THREAD;
}

static int irq_setup_forced_threading(struct irqaction *new)
{
    if (!force_irqthreads())
        return 0;

    panic("%s: END!\n", __func__);
}

static int irq_request_resources(struct irq_desc *desc)
{
    struct irq_data *d = &desc->irq_data;
    struct irq_chip *c = d->chip;

    return c->irq_request_resources ? c->irq_request_resources(d) : 0;
}

static void irq_release_resources(struct irq_desc *desc)
{
    struct irq_data *d = &desc->irq_data;
    struct irq_chip *c = d->chip;

    if (c->irq_release_resources)
        c->irq_release_resources(d);
}

void __enable_irq(struct irq_desc *desc)
{
    switch (desc->depth) {
    case 0:
 err_out:
        WARN(1, KERN_WARNING "Unbalanced enable for IRQ %d\n",
             irq_desc_get_irq(desc));
        break;
    case 1: {
        if (desc->istate & IRQS_SUSPENDED)
            goto err_out;
        /* Prevent probing on this irq: */
        irq_settings_set_noprobe(desc);
        /*
         * Call irq_startup() not irq_enable() here because the
         * interrupt might be marked NOAUTOEN. So irq_startup()
         * needs to be invoked when it gets enabled the first
         * time. If it was already started up, then irq_startup()
         * will invoke irq_enable() under the hood.
         */
        irq_startup(desc, IRQ_RESEND, IRQ_START_FORCE);
        break;
    }
    default:
        desc->depth--;
    }
}

/*
 * Internal function to wake up a interrupt thread and wait until it is
 * ready.
 */
static void wake_up_and_wait_for_irq_thread_ready(struct irq_desc *desc,
                          struct irqaction *action)
{
    if (!action || !action->thread)
        return;

    wake_up_process(action->thread);
#if 0
    wait_event(desc->wait_for_threads,
               test_bit(IRQTF_READY, &action->thread_flags));
#endif
}

/*
 * Internal function to register an irqaction - typically used to
 * allocate special interrupts that are part of the architecture.
 *
 * Locking rules:
 *
 * desc->request_mutex  Provides serialization against a concurrent free_irq()
 *   chip_bus_lock  Provides serialization for slow bus operations
 *     desc->lock   Provides serialization against hard interrupts
 *
 * chip_bus_lock and desc->lock are sufficient for all other management and
 * interrupt related functions. desc->request_mutex solely serializes
 * request/free_irq().
 */
static int
__setup_irq(unsigned int irq,
            struct irq_desc *desc, struct irqaction *new)
{
    struct irqaction *old, **old_ptr;
    unsigned long flags, thread_mask = 0;
    int ret, nested, shared = 0;

    if (!desc)
        return -EINVAL;

    if (desc->irq_data.chip == &no_irq_chip)
        return -ENOSYS;
#if 0
    if (!try_module_get(desc->owner))
        return -ENODEV;
#endif

    new->irq = irq;

    /*
     * If the trigger type is not specified by the caller,
     * then use the default for this interrupt.
     */
    if (!(new->flags & IRQF_TRIGGER_MASK))
        new->flags |= irqd_get_trigger_type(&desc->irq_data);

    /*
     * Check whether the interrupt nests into another interrupt
     * thread.
     */
    nested = irq_settings_is_nested_thread(desc);
    if (nested) {
        panic("%s: nested!\n", __func__);
#if 0
        if (!new->thread_fn) {
            ret = -EINVAL;
            goto out_mput;
        }
        /*
         * Replace the primary handler which was provided from
         * the driver for non nested interrupt handling by the
         * dummy function which warns when called.
         */
        new->handler = irq_nested_primary_handler;
#endif
    } else {
        if (irq_settings_can_thread(desc)) {
            ret = irq_setup_forced_threading(new);
            if (ret)
                goto out_mput;
        }
    }

    /*
     * Create a handler thread when a thread function is supplied
     * and the interrupt does not nest into another interrupt
     * thread.
     */
    if (new->thread_fn && !nested) {
        panic("%s: has thread_fn!\n", __func__);
#if 0
        ret = setup_irq_thread(new, irq, false);
        if (ret)
            goto out_mput;
        if (new->secondary) {
            ret = setup_irq_thread(new->secondary, irq, true);
            if (ret)
                goto out_thread;
        }
#endif
    }

    /*
     * Drivers are often written to work w/o knowledge about the
     * underlying irq chip implementation, so a request for a
     * threaded irq without a primary hard irq context handler
     * requires the ONESHOT flag to be set. Some irq chips like
     * MSI based interrupts are per se one shot safe. Check the
     * chip flags, so we can avoid the unmask dance at the end of
     * the threaded handler for those.
     */
    if (desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)
        new->flags &= ~IRQF_ONESHOT;

    /*
     * Protects against a concurrent __free_irq() call which might wait
     * for synchronize_hardirq() to complete without holding the optional
     * chip bus lock and desc->lock. Also protects against handing out
     * a recycled oneshot thread_mask bit while it's still in use by
     * its previous owner.
     */
    mutex_lock(&desc->request_mutex);

    /*
     * Acquire bus lock as the irq_request_resources() callback below
     * might rely on the serialization or the magic power management
     * functions which are abusing the irq_bus_lock() callback,
     */
    chip_bus_lock(desc);

    /* First installed action requests resources. */
    if (!desc->action) {
        ret = irq_request_resources(desc);
        if (ret) {
            pr_err("Failed to request resources for %s (irq %d) "
                   "on irqchip %s\n",
                   new->name, irq, desc->irq_data.chip->name);
            goto out_bus_unlock;
        }
    }

    /*
     * The following block of code has to be executed atomically
     * protected against a concurrent interrupt and any of the other
     * management calls which are not serialized via
     * desc->request_mutex or the optional bus lock.
     */
    raw_spin_lock_irqsave(&desc->lock, flags);
    old_ptr = &desc->action;
    old = *old_ptr;
    if (old) {
        panic("%s: has old!\n", __func__);
    }

    /*
     * Setup the thread mask for this irqaction for ONESHOT. For
     * !ONESHOT irqs the thread mask is 0 so we can avoid a
     * conditional in irq_wake_thread().
     */
    if (new->flags & IRQF_ONESHOT) {
        panic("%s: IRQF_ONESHOT!\n", __func__);
    } else if (new->handler == irq_default_primary_handler &&
               !(desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)) {
        /*
         * The interrupt was requested with handler = NULL, so
         * we use the default primary handler for it. But it
         * does not have the oneshot flag set. In combination
         * with level interrupts this is deadly, because the
         * default primary handler just wakes the thread, then
         * the irq lines is reenabled, but the device still
         * has the level irq asserted. Rinse and repeat....
         *
         * While this works for edge type interrupts, we play
         * it safe and reject unconditionally because we can't
         * say for sure which type this interrupt really
         * has. The type flags are unreliable as the
         * underlying chip implementation can override them.
         */
        pr_err("Threaded irq requested with handler=NULL "
               "and !ONESHOT for %s (irq %d)\n",
               new->name, irq);
        ret = -EINVAL;
        goto out_unlock;
    }

    if (!shared) {
        /* Setup the type (level, edge polarity) if configured: */
        if (new->flags & IRQF_TRIGGER_MASK) {
            ret = __irq_set_trigger(desc,
                                    new->flags & IRQF_TRIGGER_MASK);

            if (ret)
                goto out_unlock;
        }

        /*
         * Activate the interrupt. That activation must happen
         * independently of IRQ_NOAUTOEN. request_irq() can fail
         * and the callers are supposed to handle
         * that. enable_irq() of an interrupt requested with
         * IRQ_NOAUTOEN is not supposed to fail. The activation
         * keeps it in shutdown mode, it merily associates
         * resources if necessary and if that's not possible it
         * fails. Interrupts which are in managed shutdown mode
         * will simply ignore that activation request.
         */
        ret = irq_activate(desc);
        if (ret)
            goto out_unlock;

        desc->istate &= ~(IRQS_AUTODETECT | IRQS_SPURIOUS_DISABLED | \
                          IRQS_ONESHOT | IRQS_WAITING);
        irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);

        if (new->flags & IRQF_PERCPU) {
            panic("%s: IRQF_PERCPU!\n", __func__);
#if 0
            irqd_set(&desc->irq_data, IRQD_PER_CPU);
            irq_settings_set_per_cpu(desc);
            if (new->flags & IRQF_NO_DEBUG)
                irq_settings_set_no_debug(desc);
#endif
        }

        if (noirqdebug)
            irq_settings_set_no_debug(desc);

        if (new->flags & IRQF_ONESHOT)
            desc->istate |= IRQS_ONESHOT;

        /* Exclude IRQ from balancing if requested */
        if (new->flags & IRQF_NOBALANCING) {
            irq_settings_set_no_balancing(desc);
            irqd_set(&desc->irq_data, IRQD_NO_BALANCING);
        }

        if (!(new->flags & IRQF_NO_AUTOEN) &&
            irq_settings_can_autoenable(desc)) {
            irq_startup(desc, IRQ_RESEND, IRQ_START_COND);
        } else {
            /*
             * Shared interrupts do not go well with disabling
             * auto enable. The sharing interrupt might request
             * it while it's still disabled and then wait for
             * interrupts forever.
             */
            WARN_ON_ONCE(new->flags & IRQF_SHARED);
            /* Undo nested disables: */
            desc->depth = 1;
        }
    } else if (new->flags & IRQF_TRIGGER_MASK) {
        unsigned int nmsk = new->flags & IRQF_TRIGGER_MASK;
        unsigned int omsk = irqd_get_trigger_type(&desc->irq_data);

        if (nmsk != omsk)
            /* hope the handler works with current  trigger mode */
            pr_warn("irq %d uses trigger mode %u; requested %u\n",
                    irq, omsk, nmsk);
    }

    *old_ptr = new;

#if 0
    irq_pm_install_action(desc, new);
#endif

    /* Reset broken irq detection when installing new handler */
    desc->irq_count = 0;
    desc->irqs_unhandled = 0;

    /*
     * Check whether we disabled the irq via the spurious handler
     * before. Reenable it and give it another chance.
     */
    if (shared && (desc->istate & IRQS_SPURIOUS_DISABLED)) {
        desc->istate &= ~IRQS_SPURIOUS_DISABLED;
        __enable_irq(desc);
    }

    raw_spin_unlock_irqrestore(&desc->lock, flags);
    chip_bus_sync_unlock(desc);
    mutex_unlock(&desc->request_mutex);

    wake_up_and_wait_for_irq_thread_ready(desc, new);
    wake_up_and_wait_for_irq_thread_ready(desc, new->secondary);

#if 0
    register_irq_proc(irq, desc);
    new->dir = NULL;
    register_handler_proc(irq, new);
#endif
    return 0;

mismatch:
    if (!(new->flags & IRQF_PROBE_SHARED)) {
        pr_err("Flags mismatch irq %d. %08x (%s) vs. %08x (%s)\n",
               irq, new->flags, new->name, old->flags, old->name);
    }
    ret = -EBUSY;

 out_unlock:
    raw_spin_unlock_irqrestore(&desc->lock, flags);

    if (!desc->action)
        irq_release_resources(desc);

 out_bus_unlock:
    chip_bus_sync_unlock(desc);
    mutex_unlock(&desc->request_mutex);

 out_thread:
    if (new->thread) {
        struct task_struct *t = new->thread;

        new->thread = NULL;
        kthread_stop(t);
        put_task_struct(t);
    }
    if (new->secondary && new->secondary->thread) {
        struct task_struct *t = new->secondary->thread;

        new->secondary->thread = NULL;
        kthread_stop(t);
        put_task_struct(t);
    }

 out_mput:
    //module_put(desc->owner);
    return ret;
}

/**
 *  request_threaded_irq - allocate an interrupt line
 *  @irq: Interrupt line to allocate
 *  @handler: Function to be called when the IRQ occurs.
 *        Primary handler for threaded interrupts.
 *        If handler is NULL and thread_fn != NULL
 *        the default primary handler is installed.
 *  @thread_fn: Function called from the irq handler thread
 *          If NULL, no irq thread is created
 *  @irqflags: Interrupt type flags
 *  @devname: An ascii name for the claiming device
 *  @dev_id: A cookie passed back to the handler function
 *
 *  This call allocates interrupt resources and enables the
 *  interrupt line and IRQ handling. From the point this
 *  call is made your handler function may be invoked. Since
 *  your handler function must clear any interrupt the board
 *  raises, you must take care both to initialise your hardware
 *  and to set up the interrupt handler in the right order.
 *
 *  If you want to set up a threaded irq handler for your device
 *  then you need to supply @handler and @thread_fn. @handler is
 *  still called in hard interrupt context and has to check
 *  whether the interrupt originates from the device. If yes it
 *  needs to disable the interrupt on the device and return
 *  IRQ_WAKE_THREAD which will wake up the handler thread and run
 *  @thread_fn. This split handler design is necessary to support
 *  shared interrupts.
 *
 *  Dev_id must be globally unique. Normally the address of the
 *  device data structure is used as the cookie. Since the handler
 *  receives this value it makes sense to use it.
 *
 *  If your interrupt is shared you must pass a non NULL dev_id
 *  as this is required when freeing the interrupt.
 *
 *  Flags:
 *
 *  IRQF_SHARED     Interrupt is shared
 *  IRQF_TRIGGER_*      Specify active edge(s) or level
 *  IRQF_ONESHOT        Run thread_fn with interrupt line masked
 */
int request_threaded_irq(unsigned int irq, irq_handler_t handler,
                         irq_handler_t thread_fn, unsigned long irqflags,
                         const char *devname, void *dev_id)
{
    struct irqaction *action;
    struct irq_desc *desc;
    int retval;

    if (irq == IRQ_NOTCONNECTED)
        return -ENOTCONN;

    /*
     * Sanity-check: shared interrupts must pass in a real dev-ID,
     * otherwise we'll have trouble later trying to figure out
     * which interrupt is which (messes up the interrupt freeing
     * logic etc).
     *
     * Also shared interrupts do not go well with disabling auto enable.
     * The sharing interrupt might request it while it's still disabled
     * and then wait for interrupts forever.
     *
     * Also IRQF_COND_SUSPEND only makes sense for shared interrupts and
     * it cannot be set along with IRQF_NO_SUSPEND.
     */
    if (((irqflags & IRQF_SHARED) && !dev_id) ||
        ((irqflags & IRQF_SHARED) && (irqflags & IRQF_NO_AUTOEN)) ||
        (!(irqflags & IRQF_SHARED) && (irqflags & IRQF_COND_SUSPEND)) ||
        ((irqflags & IRQF_NO_SUSPEND) && (irqflags & IRQF_COND_SUSPEND)))
        return -EINVAL;

    desc = irq_to_desc(irq);
    if (!desc)
        return -EINVAL;

    if (!irq_settings_can_request(desc) ||
        WARN_ON(irq_settings_is_per_cpu_devid(desc)))
        return -EINVAL;

    if (!handler) {
        if (!thread_fn)
            return -EINVAL;
        handler = irq_default_primary_handler;
    }

    action = kzalloc(sizeof(struct irqaction), GFP_KERNEL);
    if (!action)
        return -ENOMEM;

    action->handler = handler;
    action->thread_fn = thread_fn;
    action->flags = irqflags;
    action->name = devname;
    action->dev_id = dev_id;

#if 0
    retval = irq_chip_pm_get(&desc->irq_data);
    if (retval < 0) {
        kfree(action);
        return retval;
    }
#endif

    retval = __setup_irq(irq, desc, action);

    if (retval) {
#if 0
        irq_chip_pm_put(&desc->irq_data);
#endif
        kfree(action->secondary);
        kfree(action);
    }

    return retval;
}
EXPORT_SYMBOL(request_threaded_irq);
