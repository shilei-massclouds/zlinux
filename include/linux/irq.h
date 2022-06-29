/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQ_H
#define _LINUX_IRQ_H

/*
 * Please do not include this file in generic code.  There is currently
 * no requirement for any architecture to implement anything held
 * within this file.
 *
 * Thanks. --rmk
 */
#include <linux/cache.h>
#include <linux/spinlock.h>
#include <linux/cpumask.h>
#if 0
#include <linux/irqhandler.h>
#include <linux/irqreturn.h>
#endif
#include <linux/irqnr.h>
#include <linux/topology.h>
#include <linux/io.h>
#include <linux/slab.h>

#include <asm/ptrace.h>
#include <asm/irq.h>
#include <asm/irq_regs.h>

/*
 * Bit masks for irq_common_data.state_use_accessors
 *
 * IRQD_TRIGGER_MASK        - Mask for the trigger type bits
 * IRQD_SETAFFINITY_PENDING - Affinity setting is pending
 * IRQD_ACTIVATED       - Interrupt has already been activated
 * IRQD_NO_BALANCING        - Balancing disabled for this IRQ
 * IRQD_PER_CPU         - Interrupt is per cpu
 * IRQD_AFFINITY_SET        - Interrupt affinity was set
 * IRQD_LEVEL           - Interrupt is level triggered
 * IRQD_WAKEUP_STATE        - Interrupt is configured for wakeup
 *                from suspend
 * IRQD_MOVE_PCNTXT     - Interrupt can be moved in process
 *                context
 * IRQD_IRQ_DISABLED        - Disabled state of the interrupt
 * IRQD_IRQ_MASKED      - Masked state of the interrupt
 * IRQD_IRQ_INPROGRESS      - In progress state of the interrupt
 * IRQD_WAKEUP_ARMED        - Wakeup mode armed
 * IRQD_FORWARDED_TO_VCPU   - The interrupt is forwarded to a VCPU
 * IRQD_AFFINITY_MANAGED    - Affinity is auto-managed by the kernel
 * IRQD_IRQ_STARTED     - Startup state of the interrupt
 * IRQD_MANAGED_SHUTDOWN    - Interrupt was shutdown due to empty affinity
 *                mask. Applies only to affinity managed irqs.
 * IRQD_SINGLE_TARGET       - IRQ allows only a single affinity target
 * IRQD_DEFAULT_TRIGGER_SET - Expected trigger already been set
 * IRQD_CAN_RESERVE     - Can use reservation mode
 * IRQD_MSI_NOMASK_QUIRK    - Non-maskable MSI quirk for affinity change
 *                required
 * IRQD_HANDLE_ENFORCE_IRQCTX   - Enforce that handle_irq_*() is only invoked
 *                from actual interrupt context.
 * IRQD_AFFINITY_ON_ACTIVATE    - Affinity is set on activation. Don't call
 *                irq_chip::irq_set_affinity() when deactivated.
 * IRQD_IRQ_ENABLED_ON_SUSPEND  - Interrupt is enabled on suspend by irq pm if
 *                irqchip have flag IRQCHIP_ENABLE_WAKEUP_ON_SUSPEND set.
 */
enum {
    IRQD_TRIGGER_MASK           = 0xf,
    IRQD_SETAFFINITY_PENDING    = (1 <<  8),
    IRQD_ACTIVATED              = (1 <<  9),
    IRQD_NO_BALANCING           = (1 << 10),
    IRQD_PER_CPU                = (1 << 11),
    IRQD_AFFINITY_SET           = (1 << 12),
    IRQD_LEVEL                  = (1 << 13),
    IRQD_WAKEUP_STATE           = (1 << 14),
    IRQD_MOVE_PCNTXT            = (1 << 15),
    IRQD_IRQ_DISABLED           = (1 << 16),
    IRQD_IRQ_MASKED             = (1 << 17),
    IRQD_IRQ_INPROGRESS         = (1 << 18),
    IRQD_WAKEUP_ARMED           = (1 << 19),
    IRQD_FORWARDED_TO_VCPU      = (1 << 20),
    IRQD_AFFINITY_MANAGED       = (1 << 21),
    IRQD_IRQ_STARTED            = (1 << 22),
    IRQD_MANAGED_SHUTDOWN       = (1 << 23),
    IRQD_SINGLE_TARGET          = (1 << 24),
    IRQD_DEFAULT_TRIGGER_SET    = (1 << 25),
    IRQD_CAN_RESERVE            = (1 << 26),
    IRQD_MSI_NOMASK_QUIRK       = (1 << 27),
    IRQD_HANDLE_ENFORCE_IRQCTX  = (1 << 28),
    IRQD_AFFINITY_ON_ACTIVATE   = (1 << 29),
    IRQD_IRQ_ENABLED_ON_SUSPEND = (1 << 30),
};

#define __irqd_to_state(d) ACCESS_PRIVATE((d)->common, state_use_accessors)

/**
 * struct irq_common_data - per irq data shared by all irqchips
 * @state_use_accessors: status information for irq chip functions.
 *          Use accessor functions to deal with it
 * @handler_data:   per-IRQ data for the irq_chip methods
 * @affinity:       IRQ affinity on SMP. If this is an IPI
 *          related irq, then this is the mask of the
 *          CPUs to which an IPI can be sent.
 * @effective_affinity: The effective IRQ affinity on SMP as some irq
 *          chips do not allow multi CPU destinations.
 *          A subset of @affinity.
 * @msi_desc:       MSI descriptor
 * @ipi_offset:     Offset of first IPI target cpu in @affinity. Optional.
 */
struct irq_common_data {
    unsigned int        __private state_use_accessors;
    void                *handler_data;
#if 0
    struct msi_desc     *msi_desc;
    cpumask_var_t       affinity;
#endif
};

/**
 * struct irq_data - per irq chip data passed down to chip functions
 * @mask:       precomputed bitmask for accessing the chip registers
 * @irq:        interrupt number
 * @hwirq:      hardware interrupt number, local to the interrupt domain
 * @common:     point to data shared by all irqchips
 * @chip:       low level interrupt hardware access
 * @domain:     Interrupt translation domain; responsible for mapping
 *          between hwirq number and linux irq number.
 * @parent_data:    pointer to parent struct irq_data to support hierarchy
 *          irq_domain
 * @chip_data:      platform-specific per-chip private data for the chip
 *          methods, to allow shared chip implementations
 */
struct irq_data {
    u32                 mask;
    unsigned int        irq;
    unsigned long       hwirq;
    struct irq_common_data  *common;
    struct irq_chip     *chip;
    struct irq_domain   *domain;
    struct irq_data     *parent_data;
    void                *chip_data;
};

extern struct irq_data *irq_get_irq_data(unsigned int irq);

static inline u32 irqd_get_trigger_type(struct irq_data *d)
{
    return __irqd_to_state(d) & IRQD_TRIGGER_MASK;
}

/*
 * Registers a generic IRQ handling function as the top-level IRQ handler in
 * the system, which is generally the first C code called from an assembly
 * architecture-specific interrupt handler.
 *
 * Returns 0 on success, or -EBUSY if an IRQ handler has already been
 * registered.
 */
int __init set_handle_irq(void (*handle_irq)(struct pt_regs *));

/*
 * Allows interrupt handlers to find the irqchip that's been registered as the
 * top-level IRQ handler.
 */
extern void (*handle_arch_irq)(struct pt_regs *) __ro_after_init;
asmlinkage void generic_handle_arch_irq(struct pt_regs *regs);

#include <linux/irqdesc.h>

#endif /* _LINUX_IRQ_H */
