/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQ_WORK_H
#define _LINUX_IRQ_WORK_H

#include <linux/smp_types.h>
#include <linux/rcuwait.h>

/*
 * An entry can be in one of four states:
 *
 * free      NULL, 0 -> {claimed}       : free to be used
 * claimed   NULL, 3 -> {pending}       : claimed to be enqueued
 * pending   next, 3 -> {busy}          : queued, pending callback
 * busy      NULL, 2 -> {free, claimed} : callback in progress, can be claimed
 */

struct irq_work {
    struct __call_single_node node;
    void (*func)(struct irq_work *);
    struct rcuwait irqwait;
};

#define __IRQ_WORK_INIT(_func, _flags) (struct irq_work){   \
    .node = { .u_flags = (_flags), },           \
    .func = (_func),                    \
    .irqwait = __RCUWAIT_INITIALIZER(irqwait),      \
}

#define IRQ_WORK_INIT(_func) __IRQ_WORK_INIT(_func, 0)
#define IRQ_WORK_INIT_LAZY(_func) __IRQ_WORK_INIT(_func, IRQ_WORK_LAZY)
#define IRQ_WORK_INIT_HARD(_func) \
    __IRQ_WORK_INIT(_func, IRQ_WORK_HARD_IRQ)

#include <asm/irq_work.h>

void irq_work_run(void);
bool irq_work_needs_cpu(void);
void irq_work_single(void *arg);

bool irq_work_queue(struct irq_work *work);

bool irq_work_queue_on(struct irq_work *work, int cpu);

#endif /* _LINUX_IRQ_WORK_H */
