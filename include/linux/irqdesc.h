/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQDESC_H
#define _LINUX_IRQDESC_H

#include <linux/rcupdate.h>
#include <linux/kobject.h>
#include <linux/mutex.h>

/*
 * Core internal functions to deal with irq descriptors
 */

struct irq_affinity_notify;
struct proc_dir_entry;
struct module;
struct irq_desc;
struct irq_domain;
struct pt_regs;

/**
 * struct irq_desc - interrupt descriptor
 * @irq_common_data:    per irq and chip data passed down to chip functions
 * @kstat_irqs:     irq stats per cpu
 * @handle_irq:     highlevel irq-events handler
 * @action:     the irq action chain
 * @status_use_accessors: status information
 * @core_internal_state__do_not_mess_with_it: core internal status information
 * @depth:      disable-depth, for nested irq_disable() calls
 * @wake_depth:     enable depth, for multiple irq_set_irq_wake() callers
 * @tot_count:      stats field for non-percpu irqs
 * @irq_count:      stats field to detect stalled irqs
 * @last_unhandled: aging timer for unhandled count
 * @irqs_unhandled: stats field for spurious unhandled interrupts
 * @threads_handled:    stats field for deferred spurious detection of threaded handlers
 * @threads_handled_last: comparator field for deferred spurious detection of threaded handlers
 * @lock:       locking for SMP
 * @affinity_hint:  hint to user space for preferred irq affinity
 * @affinity_notify:    context for notification of affinity changes
 * @pending_mask:   pending rebalanced interrupts
 * @threads_oneshot:    bitfield to handle shared oneshot threads
 * @threads_active: number of irqaction threads currently running
 * @wait_for_threads:   wait queue for sync_irq to wait for threaded handlers
 * @nr_actions:     number of installed actions on this descriptor
 * @no_suspend_depth:   number of irqactions on a irq descriptor with
 *          IRQF_NO_SUSPEND set
 * @force_resume_depth: number of irqactions on a irq descriptor with
 *          IRQF_FORCE_RESUME set
 * @rcu:        rcu head for delayed free
 * @kobj:       kobject used to represent this struct in sysfs
 * @request_mutex:  mutex to protect request/free before locking desc->lock
 * @dir:        /proc/irq/ procfs entry
 * @debugfs_file:   dentry for the debugfs file
 * @name:       flow handler name for /proc/interrupts output
 */
struct irq_desc {
    struct irq_common_data  irq_common_data;
    struct irq_data     irq_data;
    unsigned int __percpu   *kstat_irqs;
    irq_flow_handler_t  handle_irq;
    struct irqaction    *action;    /* IRQ action list */
    unsigned int        status_use_accessors;
    unsigned int        core_internal_state__do_not_mess_with_it;
    unsigned int        depth;      /* nested irq disables */
    unsigned int        wake_depth; /* nested wake enables */
    unsigned int        tot_count;
    unsigned int        irq_count;  /* For detecting broken IRQs */
    unsigned long       last_unhandled; /* Aging timer for unhandled count */
    unsigned int        irqs_unhandled;
    atomic_t            threads_handled;
    int                 threads_handled_last;
    raw_spinlock_t      lock;
    struct cpumask      *percpu_enabled;
    const struct cpumask    *percpu_affinity;
    const struct cpumask    *affinity_hint;
    struct irq_affinity_notify *affinity_notify;

    unsigned long       threads_oneshot;
    atomic_t            threads_active;
#if 0
    wait_queue_head_t   wait_for_threads;
#endif

    struct proc_dir_entry   *dir;

    struct rcu_head     rcu;
    struct kobject      kobj;

    struct mutex        request_mutex;
    int                 parent_irq;
    struct module       *owner;
    const char          *name;
} ____cacheline_internodealigned_in_smp;

int generic_handle_domain_irq(struct irq_domain *domain, unsigned int hwirq);

static inline struct irq_desc *irq_data_to_desc(struct irq_data *data)
{
    return container_of(data->common, struct irq_desc, irq_common_data);
}

static inline struct irq_chip *irq_desc_get_chip(struct irq_desc *desc)
{
    return desc->irq_data.chip;
}

static inline unsigned int irq_desc_get_irq(struct irq_desc *desc)
{
    return desc->irq_data.irq;
}

static inline struct irq_data *irq_desc_get_irq_data(struct irq_desc *desc)
{
    return &desc->irq_data;
}

/*
 * Architectures call this to let the generic IRQ layer
 * handle an interrupt.
 */
static inline void generic_handle_irq_desc(struct irq_desc *desc)
{
    desc->handle_irq(desc);
}

#endif /* _LINUX_IRQDESC_H */
