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

#endif /* _LINUX_IRQ_WORK_H */
