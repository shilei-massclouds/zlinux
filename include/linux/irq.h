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
#include <linux/irqhandler.h>
#include <linux/irqreturn.h>
#include <linux/irqnr.h>
#include <linux/topology.h>
#include <linux/io.h>
#include <linux/slab.h>

#include <asm/irq.h>
#include <asm/ptrace.h>
#include <asm/irq_regs.h>

#ifndef ARCH_IRQ_INIT_FLAGS
# define ARCH_IRQ_INIT_FLAGS    0
#endif

#define IRQ_DEFAULT_INIT_FLAGS  ARCH_IRQ_INIT_FLAGS

struct seq_file;
struct module;
struct msi_msg;
struct irq_affinity_desc;
enum irqchip_irq_state;

/*
 * IRQ line status.
 *
 * Bits 0-7 are the same as the IRQF_* bits in linux/interrupt.h
 *
 * IRQ_TYPE_NONE        - default, unspecified type
 * IRQ_TYPE_EDGE_RISING     - rising edge triggered
 * IRQ_TYPE_EDGE_FALLING    - falling edge triggered
 * IRQ_TYPE_EDGE_BOTH       - rising and falling edge triggered
 * IRQ_TYPE_LEVEL_HIGH      - high level triggered
 * IRQ_TYPE_LEVEL_LOW       - low level triggered
 * IRQ_TYPE_LEVEL_MASK      - Mask to filter out the level bits
 * IRQ_TYPE_SENSE_MASK      - Mask for all the above bits
 * IRQ_TYPE_DEFAULT     - For use by some PICs to ask irq_set_type
 *                to setup the HW to a sane default (used
 *                                by irqdomain map() callbacks to synchronize
 *                                the HW state and SW flags for a newly
 *                                allocated descriptor).
 *
 * IRQ_TYPE_PROBE       - Special flag for probing in progress
 *
 * Bits which can be modified via irq_set/clear/modify_status_flags()
 * IRQ_LEVEL            - Interrupt is level type. Will be also
 *                updated in the code when the above trigger
 *                bits are modified via irq_set_irq_type()
 * IRQ_PER_CPU          - Mark an interrupt PER_CPU. Will protect
 *                it from affinity setting
 * IRQ_NOPROBE          - Interrupt cannot be probed by autoprobing
 * IRQ_NOREQUEST        - Interrupt cannot be requested via
 *                request_irq()
 * IRQ_NOTHREAD         - Interrupt cannot be threaded
 * IRQ_NOAUTOEN         - Interrupt is not automatically enabled in
 *                request/setup_irq()
 * IRQ_NO_BALANCING     - Interrupt cannot be balanced (affinity set)
 * IRQ_MOVE_PCNTXT      - Interrupt can be migrated from process context
 * IRQ_NESTED_THREAD        - Interrupt nests into another thread
 * IRQ_PER_CPU_DEVID        - Dev_id is a per-cpu variable
 * IRQ_IS_POLLED        - Always polled by another interrupt. Exclude
 *                it from the spurious interrupt detection
 *                mechanism and from core side polling.
 * IRQ_DISABLE_UNLAZY       - Disable lazy irq disable
 * IRQ_HIDDEN           - Don't show up in /proc/interrupts
 * IRQ_NO_DEBUG         - Exclude from note_interrupt() debugging
 */
enum {
    IRQ_TYPE_NONE       = 0x00000000,
    IRQ_TYPE_EDGE_RISING    = 0x00000001,
    IRQ_TYPE_EDGE_FALLING   = 0x00000002,
    IRQ_TYPE_EDGE_BOTH  = (IRQ_TYPE_EDGE_FALLING | IRQ_TYPE_EDGE_RISING),
    IRQ_TYPE_LEVEL_HIGH = 0x00000004,
    IRQ_TYPE_LEVEL_LOW  = 0x00000008,
    IRQ_TYPE_LEVEL_MASK = (IRQ_TYPE_LEVEL_LOW | IRQ_TYPE_LEVEL_HIGH),
    IRQ_TYPE_SENSE_MASK = 0x0000000f,
    IRQ_TYPE_DEFAULT    = IRQ_TYPE_SENSE_MASK,

    IRQ_TYPE_PROBE      = 0x00000010,

    IRQ_LEVEL           = (1 <<  8),
    IRQ_PER_CPU         = (1 <<  9),
    IRQ_NOPROBE         = (1 << 10),
    IRQ_NOREQUEST       = (1 << 11),
    IRQ_NOAUTOEN        = (1 << 12),
    IRQ_NO_BALANCING    = (1 << 13),
    IRQ_MOVE_PCNTXT     = (1 << 14),
    IRQ_NESTED_THREAD   = (1 << 15),
    IRQ_NOTHREAD        = (1 << 16),
    IRQ_PER_CPU_DEVID   = (1 << 17),
    IRQ_IS_POLLED       = (1 << 18),
    IRQ_DISABLE_UNLAZY  = (1 << 19),
    IRQ_HIDDEN          = (1 << 20),
    IRQ_NO_DEBUG        = (1 << 21),
};

/*
 * Return value for chip->irq_set_affinity()
 *
 * IRQ_SET_MASK_OK  - OK, core updates irq_common_data.affinity
 * IRQ_SET_MASK_NOCPY   - OK, chip did update irq_common_data.affinity
 * IRQ_SET_MASK_OK_DONE - Same as IRQ_SET_MASK_OK for core. Special code to
 *            support stacked irqchips, which indicates skipping
 *            all descendant irqchips.
 */
enum {
    IRQ_SET_MASK_OK = 0,
    IRQ_SET_MASK_OK_NOCOPY,
    IRQ_SET_MASK_OK_DONE,
};

#define IRQF_MODIFY_MASK \
    (IRQ_TYPE_SENSE_MASK | IRQ_NOPROBE | IRQ_NOREQUEST | \
     IRQ_NOAUTOEN | IRQ_MOVE_PCNTXT | IRQ_LEVEL | IRQ_NO_BALANCING | \
     IRQ_PER_CPU | IRQ_NESTED_THREAD | IRQ_NOTHREAD | IRQ_PER_CPU_DEVID | \
     IRQ_IS_POLLED | IRQ_DISABLE_UNLAZY | IRQ_HIDDEN)

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
    struct msi_desc     *msi_desc;
    cpumask_var_t       affinity;
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

extern void
__irq_set_handler(unsigned int irq, irq_flow_handler_t handle,
                  int is_chained, const char *name);

extern int irq_set_handler_data(unsigned int irq, void *data);

#define __irqd_to_state(d) ACCESS_PRIVATE((d)->common, state_use_accessors)

static inline bool irqd_is_setaffinity_pending(struct irq_data *d)
{
    return __irqd_to_state(d) & IRQD_SETAFFINITY_PENDING;
}

static inline void irqd_clr_activated(struct irq_data *d)
{
    __irqd_to_state(d) &= ~IRQD_ACTIVATED;
}

static inline bool irqd_is_activated(struct irq_data *d)
{
    return __irqd_to_state(d) & IRQD_ACTIVATED;
}

static inline void irqd_set_activated(struct irq_data *d)
{
    __irqd_to_state(d) |= IRQD_ACTIVATED;
}

static inline bool irqd_is_started(struct irq_data *d)
{
    return __irqd_to_state(d) & IRQD_IRQ_STARTED;
}

static inline bool irqd_irq_masked(struct irq_data *d)
{
    return __irqd_to_state(d) & IRQD_IRQ_MASKED;
}

static inline bool irqd_irq_disabled(struct irq_data *d)
{
    return __irqd_to_state(d) & IRQD_IRQ_DISABLED;
}

static inline bool irqd_affinity_is_managed(struct irq_data *d)
{
    return __irqd_to_state(d) & IRQD_AFFINITY_MANAGED;
}

static inline u32 irqd_get_trigger_type(struct irq_data *d)
{
    return __irqd_to_state(d) & IRQD_TRIGGER_MASK;
}

static inline bool irqd_can_balance(struct irq_data *d)
{
    return !(__irqd_to_state(d) & (IRQD_PER_CPU | IRQD_NO_BALANCING));
}

/*
 * Must only be called inside irq_chip.irq_set_type() functions or
 * from the DT/ACPI setup code.
 */
static inline void irqd_set_trigger_type(struct irq_data *d, u32 type)
{
    __irqd_to_state(d) &= ~IRQD_TRIGGER_MASK;
    __irqd_to_state(d) |= type & IRQD_TRIGGER_MASK;
    __irqd_to_state(d) |= IRQD_DEFAULT_TRIGGER_SET;
}

static inline bool irqd_affinity_on_activate(struct irq_data *d)
{
    return __irqd_to_state(d) & IRQD_AFFINITY_ON_ACTIVATE;
}

#undef __irqd_to_state

/**
 * struct irq_chip - hardware interrupt chip descriptor
 *
 * @name:       name for /proc/interrupts
 * @irq_startup:    start up the interrupt (defaults to ->enable if NULL)
 * @irq_shutdown:   shut down the interrupt (defaults to ->disable if NULL)
 * @irq_enable:     enable the interrupt (defaults to chip->unmask if NULL)
 * @irq_disable:    disable the interrupt
 * @irq_ack:        start of a new interrupt
 * @irq_mask:       mask an interrupt source
 * @irq_mask_ack:   ack and mask an interrupt source
 * @irq_unmask:     unmask an interrupt source
 * @irq_eoi:        end of interrupt
 * @irq_set_affinity:   Set the CPU affinity on SMP machines. If the force
 *          argument is true, it tells the driver to
 *          unconditionally apply the affinity setting. Sanity
 *          checks against the supplied affinity mask are not
 *          required. This is used for CPU hotplug where the
 *          target CPU is not yet set in the cpu_online_mask.
 * @irq_retrigger:  resend an IRQ to the CPU
 * @irq_set_type:   set the flow type (IRQ_TYPE_LEVEL/etc.) of an IRQ
 * @irq_set_wake:   enable/disable power-management wake-on of an IRQ
 * @irq_bus_lock:   function to lock access to slow bus (i2c) chips
 * @irq_bus_sync_unlock:function to sync and unlock slow bus (i2c) chips
 * @irq_cpu_online: configure an interrupt source for a secondary CPU
 * @irq_cpu_offline:    un-configure an interrupt source for a secondary CPU
 * @irq_suspend:    function called from core code on suspend once per
 *          chip, when one or more interrupts are installed
 * @irq_resume:     function called from core code on resume once per chip,
 *          when one ore more interrupts are installed
 * @irq_pm_shutdown:    function called from core code on shutdown once per chip
 * @irq_calc_mask:  Optional function to set irq_data.mask for special cases
 * @irq_print_chip: optional to print special chip info in show_interrupts
 * @irq_request_resources:  optional to request resources before calling
 *              any other callback related to this irq
 * @irq_release_resources:  optional to release resources acquired with
 *              irq_request_resources
 * @irq_compose_msi_msg:    optional to compose message content for MSI
 * @irq_write_msi_msg:  optional to write message content for MSI
 * @irq_get_irqchip_state:  return the internal state of an interrupt
 * @irq_set_irqchip_state:  set the internal state of a interrupt
 * @irq_set_vcpu_affinity:  optional to target a vCPU in a virtual machine
 * @ipi_send_single:    send a single IPI to destination cpus
 * @ipi_send_mask:  send an IPI to destination cpus in cpumask
 * @irq_nmi_setup:  function called from core code before enabling an NMI
 * @irq_nmi_teardown:   function called from core code after disabling an NMI
 * @flags:      chip specific flags
 */
struct irq_chip {
    const char  *name;
    unsigned int (*irq_startup)(struct irq_data *data);
    void (*irq_shutdown)(struct irq_data *data);
    void (*irq_enable)(struct irq_data *data);
    void (*irq_disable)(struct irq_data *data);

    void (*irq_ack)(struct irq_data *data);
    void (*irq_mask)(struct irq_data *data);
    void (*irq_mask_ack)(struct irq_data *data);
    void (*irq_unmask)(struct irq_data *data);
    void (*irq_eoi)(struct irq_data *data);

    int  (*irq_set_affinity)(struct irq_data *data,
                             const struct cpumask *dest, bool force);
    int  (*irq_retrigger)(struct irq_data *data);
    int  (*irq_set_type)(struct irq_data *data, unsigned int flow_type);
    int  (*irq_set_wake)(struct irq_data *data, unsigned int on);

    void (*irq_bus_lock)(struct irq_data *data);
    void (*irq_bus_sync_unlock)(struct irq_data *data);

    void (*irq_suspend)(struct irq_data *data);
    void (*irq_resume)(struct irq_data *data);
    void (*irq_pm_shutdown)(struct irq_data *data);

    void (*irq_calc_mask)(struct irq_data *data);

    void (*irq_print_chip)(struct irq_data *data, struct seq_file *p);
    int  (*irq_request_resources)(struct irq_data *data);
    void (*irq_release_resources)(struct irq_data *data);

    void        (*irq_compose_msi_msg)(struct irq_data *data, struct msi_msg *msg);
    void        (*irq_write_msi_msg)(struct irq_data *data, struct msi_msg *msg);

    int     (*irq_get_irqchip_state)(struct irq_data *data, enum irqchip_irq_state which, bool *state);
    int     (*irq_set_irqchip_state)(struct irq_data *data, enum irqchip_irq_state which, bool state);

    int     (*irq_set_vcpu_affinity)(struct irq_data *data, void *vcpu_info);

    void        (*ipi_send_single)(struct irq_data *data, unsigned int cpu);
    void        (*ipi_send_mask)(struct irq_data *data, const struct cpumask *dest);

    int     (*irq_nmi_setup)(struct irq_data *data);
    void        (*irq_nmi_teardown)(struct irq_data *data);

    unsigned long   flags;
};

extern struct irq_data *irq_get_irq_data(unsigned int irq);

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

int __irq_alloc_descs(int irq, unsigned int from, unsigned int cnt, int node,
                      struct module *owner,
                      const struct irq_affinity_desc *affinity);

unsigned int arch_dynirq_lower_bound(unsigned int from);

extern void handle_bad_irq(struct irq_desc *desc);

/* Dummy irq-chip implementations: */
extern struct irq_chip no_irq_chip;
extern struct irq_chip dummy_irq_chip;

/*
 * irq_chip specific flags
 *
 * IRQCHIP_SET_TYPE_MASKED:           Mask before calling chip.irq_set_type()
 * IRQCHIP_EOI_IF_HANDLED:            Only issue irq_eoi() when irq was handled
 * IRQCHIP_MASK_ON_SUSPEND:           Mask non wake irqs in the suspend path
 * IRQCHIP_ONOFFLINE_ENABLED:         Only call irq_on/off_line callbacks
 *                                    when irq enabled
 * IRQCHIP_SKIP_SET_WAKE:             Skip chip.irq_set_wake(), for this irq chip
 * IRQCHIP_ONESHOT_SAFE:              One shot does not require mask/unmask
 * IRQCHIP_EOI_THREADED:              Chip requires eoi() on unmask in threaded mode
 * IRQCHIP_SUPPORTS_LEVEL_MSI:        Chip can provide two doorbells for Level MSIs
 * IRQCHIP_SUPPORTS_NMI:              Chip can deliver NMIs, only for root irqchips
 * IRQCHIP_ENABLE_WAKEUP_ON_SUSPEND:  Invokes __enable_irq()/__disable_irq() for wake irqs
 *                                    in the suspend path if they are in disabled state
 * IRQCHIP_AFFINITY_PRE_STARTUP:      Default affinity update before startup
 */
enum {
    IRQCHIP_SET_TYPE_MASKED         = (1 <<  0),
    IRQCHIP_EOI_IF_HANDLED          = (1 <<  1),
    IRQCHIP_MASK_ON_SUSPEND         = (1 <<  2),
    IRQCHIP_ONOFFLINE_ENABLED       = (1 <<  3),
    IRQCHIP_SKIP_SET_WAKE           = (1 <<  4),
    IRQCHIP_ONESHOT_SAFE            = (1 <<  5),
    IRQCHIP_EOI_THREADED            = (1 <<  6),
    IRQCHIP_SUPPORTS_LEVEL_MSI      = (1 <<  7),
    IRQCHIP_SUPPORTS_NMI            = (1 <<  8),
    IRQCHIP_ENABLE_WAKEUP_ON_SUSPEND    = (1 <<  9),
    IRQCHIP_AFFINITY_PRE_STARTUP        = (1 << 10),
};

void irq_free_descs(unsigned int irq, unsigned int cnt);
static inline void irq_free_desc(unsigned int irq)
{
    irq_free_descs(irq, 1);
}

void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set);

static inline void irq_set_status_flags(unsigned int irq, unsigned long set)
{
    irq_modify_status(irq, 0, set);
}

static inline void irq_clear_status_flags(unsigned int irq, unsigned long clr)
{
    irq_modify_status(irq, clr, 0);
}

static inline void irq_set_noprobe(unsigned int irq)
{
    irq_modify_status(irq, 0, IRQ_NOPROBE);
}

static inline void irq_set_percpu_devid_flags(unsigned int irq)
{
    irq_set_status_flags(irq,
                         IRQ_NOAUTOEN | IRQ_PER_CPU | IRQ_NOTHREAD |
                         IRQ_NOPROBE | IRQ_PER_CPU_DEVID);
}

extern int irq_set_percpu_devid(unsigned int irq);
extern int irq_set_percpu_devid_partition(unsigned int irq,
                                          const struct cpumask *affinity);

extern void handle_percpu_devid_irq(struct irq_desc *desc);

static inline struct cpumask *
irq_data_get_affinity_mask(struct irq_data *d)
{
    return d->common->affinity;
}

static inline int irq_common_data_get_node(struct irq_common_data *d)
{
    return 0;
}

static inline struct irq_chip *irq_data_get_irq_chip(struct irq_data *d)
{
    return d->chip;
}

extern void handle_fasteoi_irq(struct irq_desc *desc);

static inline
void irq_data_update_effective_affinity(struct irq_data *d,
                                        const struct cpumask *m)
{
}

static inline
struct cpumask *irq_data_get_effective_affinity_mask(struct irq_data *d)
{
    return d->common->affinity;
}

/*
 * Set a highlevel chained flow handler for a given IRQ.
 * (a chained handler is automatically enabled and set to
 *  IRQ_NOREQUEST, IRQ_NOPROBE, and IRQ_NOTHREAD)
 */
static inline void
irq_set_chained_handler(unsigned int irq, irq_flow_handler_t handle)
{
    __irq_set_handler(irq, handle, 1, NULL);
}

extern int irq_chip_retrigger_hierarchy(struct irq_data *data);

static inline int irq_data_get_node(struct irq_data *d)
{
    return irq_common_data_get_node(d->common);
}

static inline u32 irq_get_trigger_type(unsigned int irq)
{
    struct irq_data *d = irq_get_irq_data(irq);
    return d ? irqd_get_trigger_type(d) : 0;
}

static inline void *irq_data_get_irq_chip_data(struct irq_data *d)
{
    return d->chip_data;
}

#include <linux/irqdesc.h>

#endif /* _LINUX_IRQ_H */
