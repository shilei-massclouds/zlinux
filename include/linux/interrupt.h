/* SPDX-License-Identifier: GPL-2.0 */
/* interrupt.h */
#ifndef _LINUX_INTERRUPT_H
#define _LINUX_INTERRUPT_H

#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/cpumask.h>
#include <linux/irqreturn.h>
#if 0
#include <linux/hrtimer.h>
#endif
#include <linux/hardirq.h>
#include <linux/irqnr.h>
#include <linux/irqflags.h>
#include <linux/kref.h>
#if 0
#include <linux/workqueue.h>
#include <linux/jump_label.h>
#endif

#include <linux/atomic.h>
#include <asm/ptrace.h>
#include <asm/irq.h>
#include <asm/sections.h>

/**
 * struct irq_affinity_desc - Interrupt affinity descriptor
 * @mask:   cpumask to hold the affinity assignment
 * @is_managed: 1 if the interrupt is managed internally
 */
struct irq_affinity_desc {
    struct cpumask  mask;
    unsigned int    is_managed : 1;
};

typedef irqreturn_t (*irq_handler_t)(int, void *);

/**
 * struct irqaction - per interrupt action descriptor
 * @handler:    interrupt handler function
 * @name:   name of the device
 * @dev_id: cookie to identify the device
 * @percpu_dev_id:  cookie to identify the device
 * @next:   pointer to the next irqaction for shared interrupts
 * @irq:    interrupt number
 * @flags:  flags (see IRQF_* above)
 * @thread_fn:  interrupt handler function for threaded interrupts
 * @thread: thread pointer for threaded interrupts
 * @secondary:  pointer to secondary irqaction (force threading)
 * @thread_flags:   flags related to @thread
 * @thread_mask:    bitmask for keeping track of @thread activity
 * @dir:    pointer to the proc/irq/NN/name entry
 */
struct irqaction {
    irq_handler_t       handler;
    void                *dev_id;
    void __percpu       *percpu_dev_id;
    struct irqaction    *next;
    irq_handler_t       thread_fn;
    struct task_struct  *thread;
    struct irqaction    *secondary;
    unsigned int        irq;
    unsigned int        flags;
    unsigned long       thread_flags;
    unsigned long       thread_mask;
    const char          *name;
    struct proc_dir_entry   *dir;
} ____cacheline_internodealigned_in_smp;

extern cpumask_var_t irq_default_affinity;

#endif /* _LINUX_INTERRUPT_H */
