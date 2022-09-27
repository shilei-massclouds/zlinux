// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2010 Red Hat, Inc., Peter Zijlstra
 *
 * Provides a framework for enqueueing and running callbacks from hardirq
 * context. The enqueueing is NMI-safe.
 */

#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/irq_work.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/irqflags.h>
#include <linux/sched.h>
#include <linux/tick.h>
#include <linux/cpu.h>
//#include <linux/notifier.h>
#include <linux/smp.h>
#include <linux/smpboot.h>
#include <asm/processor.h>
//#include <linux/kasan.h>

static DEFINE_PER_CPU(struct llist_head, raised_list);
static DEFINE_PER_CPU(struct llist_head, lazy_list);
static DEFINE_PER_CPU(struct task_struct *, irq_workd);

/*
 * Claim the entry so that no one else will poke at it.
 */
static bool irq_work_claim(struct irq_work *work)
{
    int oflags;

    oflags = atomic_fetch_or(IRQ_WORK_CLAIMED | CSD_TYPE_IRQ_WORK,
                             &work->node.a_flags);
    /*
     * If the work is already pending, no need to raise the IPI.
     * The pairing smp_mb() in irq_work_single() makes sure
     * everything we did before is visible.
     */
    if (oflags & IRQ_WORK_PENDING)
        return false;
    return true;
}

/* Enqueue on current CPU, work must already be claimed and preempt disabled */
static void __irq_work_queue_local(struct irq_work *work)
{
    struct llist_head *list;
    bool rt_lazy_work = false;
    bool lazy_work = false;
    int work_flags;

    work_flags = atomic_read(&work->node.a_flags);
    if (work_flags & IRQ_WORK_LAZY)
        lazy_work = true;

    if (lazy_work || rt_lazy_work)
        list = this_cpu_ptr(&lazy_list);
    else
        list = this_cpu_ptr(&raised_list);

    if (!llist_add(&work->node.llist, list))
        return;

    /* If the work is "lazy", handle it from next tick if any */
    if (!lazy_work || tick_nohz_tick_stopped())
        arch_irq_work_raise();
}

/* Enqueue the irq work @work on the current CPU */
bool irq_work_queue(struct irq_work *work)
{
    /* Only queue if not already pending */
    if (!irq_work_claim(work))
        return false;

    /* Queue the entry and raise the IPI if needed. */
    preempt_disable();
    __irq_work_queue_local(work);
    preempt_enable();

    return true;
}
EXPORT_SYMBOL_GPL(irq_work_queue);
