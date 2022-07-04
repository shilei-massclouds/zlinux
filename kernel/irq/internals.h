/* SPDX-License-Identifier: GPL-2.0 */
/*
 * IRQ subsystem internal functions and variables:
 *
 * Do not ever include this file from anything else than
 * kernel/irq/. Do not even think about using any information outside
 * of this file for your non core code.
 */
#include <linux/irqdesc.h>
#include <linux/kernel_stat.h>
#if 0
#include <linux/pm_runtime.h>
#include <linux/sched/clock.h>
#endif

#include "settings.h"

#define IRQ_BITMAP_BITS     (NR_IRQS + 8196)

#define istate core_internal_state__do_not_mess_with_it

#define _IRQ_DESC_CHECK     (1 << 0)
#define _IRQ_DESC_PERCPU    (1 << 1)

#define IRQ_RESEND      true
#define IRQ_NORESEND    false

#define IRQ_START_FORCE true
#define IRQ_START_COND  false

/*
 * Bit masks for desc->core_internal_state__do_not_mess_with_it
 *
 * IRQS_AUTODETECT      - autodetection in progress
 * IRQS_SPURIOUS_DISABLED   - was disabled due to spurious interrupt
 *                detection
 * IRQS_POLL_INPROGRESS     - polling in progress
 * IRQS_ONESHOT         - irq is not unmasked in primary handler
 * IRQS_REPLAY          - irq is replayed
 * IRQS_WAITING         - irq is waiting
 * IRQS_PENDING         - irq is pending and replayed later
 * IRQS_SUSPENDED       - irq is suspended
 * IRQS_NMI         - irq line is used to deliver NMIs
 */
enum {
    IRQS_AUTODETECT = 0x00000001,
    IRQS_SPURIOUS_DISABLED  = 0x00000002,
    IRQS_POLL_INPROGRESS    = 0x00000008,
    IRQS_ONESHOT    = 0x00000020,
    IRQS_REPLAY     = 0x00000040,
    IRQS_WAITING    = 0x00000080,
    IRQS_PENDING    = 0x00000200,
    IRQS_SUSPENDED  = 0x00000800,
    IRQS_TIMINGS    = 0x00001000,
    IRQS_NMI        = 0x00002000,
};

extern int __irq_set_trigger(struct irq_desc *desc, unsigned long flags);
extern void __disable_irq(struct irq_desc *desc);
extern void __enable_irq(struct irq_desc *desc);

#define __irqd_to_state(d) ACCESS_PRIVATE((d)->common, state_use_accessors)

static inline void irqd_clear(struct irq_data *d, unsigned int mask)
{
    __irqd_to_state(d) &= ~mask;
}

static inline void irqd_set(struct irq_data *d, unsigned int mask)
{
    __irqd_to_state(d) |= mask;
}

static inline void irqd_set_managed_shutdown(struct irq_data *d)
{
    __irqd_to_state(d) |= IRQD_MANAGED_SHUTDOWN;
}

static inline void irqd_clr_managed_shutdown(struct irq_data *d)
{
    __irqd_to_state(d) &= ~IRQD_MANAGED_SHUTDOWN;
}

#undef __irqd_to_state

static inline int irq_desc_get_node(struct irq_desc *desc)
{
    return irq_common_data_get_node(&desc->irq_common_data);
}

extern int irq_activate(struct irq_desc *desc);
extern int irq_activate_and_startup(struct irq_desc *desc, bool resend);
extern int irq_startup(struct irq_desc *desc, bool resend, bool force);

/* Resending of interrupts :*/
int check_irq_resend(struct irq_desc *desc, bool inject);
bool irq_wait_for_poll(struct irq_desc *desc);
void __irq_wake_thread(struct irq_desc *desc, struct irqaction *action);

extern void irq_shutdown(struct irq_desc *desc);
extern void irq_shutdown_and_deactivate(struct irq_desc *desc);
extern void irq_enable(struct irq_desc *desc);
extern void irq_disable(struct irq_desc *desc);
extern void irq_percpu_enable(struct irq_desc *desc, unsigned int cpu);
extern void irq_percpu_disable(struct irq_desc *desc, unsigned int cpu);
extern void mask_irq(struct irq_desc *desc);
extern void unmask_irq(struct irq_desc *desc);
extern void unmask_threaded_irq(struct irq_desc *desc);

static inline void irq_state_set_masked(struct irq_desc *desc)
{
    irqd_set(&desc->irq_data, IRQD_IRQ_MASKED);
}

static inline void mask_ack_irq(struct irq_desc *desc)
{
    if (desc->irq_data.chip->irq_mask_ack) {
        desc->irq_data.chip->irq_mask_ack(&desc->irq_data);
        irq_state_set_masked(desc);
    } else {
        mask_irq(desc);
        if (desc->irq_data.chip->irq_ack)
            desc->irq_data.chip->irq_ack(&desc->irq_data);
    }
}

static inline void irq_state_set_disabled(struct irq_desc *desc)
{
    irqd_set(&desc->irq_data, IRQD_IRQ_DISABLED);
}

struct irq_desc *
__irq_get_desc_lock(unsigned int irq, unsigned long *flags,
                    bool bus, unsigned int check);

static inline struct irq_desc *
irq_get_desc_lock(unsigned int irq, unsigned long *flags, unsigned int check)
{
    return __irq_get_desc_lock(irq, flags, false, check);
}

/* Inline functions for support of irq chips on slow busses */
static inline void chip_bus_lock(struct irq_desc *desc)
{
    if (unlikely(desc->irq_data.chip->irq_bus_lock))
        desc->irq_data.chip->irq_bus_lock(&desc->irq_data);
}

static inline void chip_bus_sync_unlock(struct irq_desc *desc)
{
    if (unlikely(desc->irq_data.chip->irq_bus_sync_unlock))
        desc->irq_data.chip->irq_bus_sync_unlock(&desc->irq_data);
}

void __irq_put_desc_unlock(struct irq_desc *desc,
                           unsigned long flags, bool bus);

static inline void
irq_put_desc_unlock(struct irq_desc *desc, unsigned long flags)
{
    __irq_put_desc_unlock(desc, flags, false);
}

static inline struct irq_desc *
irq_get_desc_buslock(unsigned int irq, unsigned long *flags, unsigned int check)
{
    return __irq_get_desc_lock(irq, flags, true, check);
}

static inline void
irq_put_desc_busunlock(struct irq_desc *desc, unsigned long flags)
{
    __irq_put_desc_unlock(desc, flags, true);
}

extern void irq_set_thread_affinity(struct irq_desc *desc);

extern int irq_do_set_affinity(struct irq_data *data,
                               const struct cpumask *dest, bool force);

extern int irq_setup_affinity(struct irq_desc *desc);