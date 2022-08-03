/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_HARDIRQ_H
#define LINUX_HARDIRQ_H

#if 0
#include <linux/context_tracking_state.h>
#include <linux/ftrace_irq.h>
#include <linux/vtime.h>
#endif
#include <linux/preempt.h>
#include <linux/sched.h>
#include <asm/hardirq.h>

/*
 * Enter irq context (on NO_HZ, update jiffies):
 */
void irq_enter(void);

/*
 * Like irq_enter(), but RCU is already watching.
 */
void irq_enter_rcu(void);

/*
 * Exit irq context and process softirqs if needed:
 */
void irq_exit(void);

/*
 * Like irq_exit(), but return with RCU watching.
 */
void irq_exit_rcu(void);

extern void rcu_nmi_enter(void);
extern void rcu_nmi_exit(void);

/*
 * Like __irq_enter() without time accounting for fast
 * interrupts, e.g. reschedule IPI where time accounting
 * is more expensive than the actual interrupt.
 */
#define __irq_enter_raw()                   \
    do {                                    \
        preempt_count_add(HARDIRQ_OFFSET);  \
    } while (0)

#endif /* LINUX_HARDIRQ_H */
