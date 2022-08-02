// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/softirq.c
 *
 *  Copyright (C) 1992 Linus Torvalds
 *
 *  Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/local_lock.h>
#include <linux/mm.h>
#if 0
#include <linux/notifier.h>
#include <linux/freezer.h>
#include <linux/ftrace.h>
#include <linux/smpboot.h>
#endif
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/smp.h>
#if 0
#include <linux/tick.h>
#include <linux/wait_bit.h>
#endif
#include <linux/irq.h>

#if 0
#include <asm/softirq_stack.h>
#endif

DEFINE_PER_CPU_ALIGNED(irq_cpustat_t, irq_stat);
EXPORT_PER_CPU_SYMBOL(irq_stat);

DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

unsigned int __weak arch_dynirq_lower_bound(unsigned int from)
{
    return from;
}

static void __local_bh_enable(unsigned int cnt)
{
    __preempt_count_sub(cnt);
}

void __local_bh_enable_ip(unsigned long ip, unsigned int cnt)
{
    WARN_ON_ONCE(in_hardirq());

    /*
     * Keep preemption disabled until we are done with
     * softirq processing:
     */
    __preempt_count_sub(cnt - 1);

    if (unlikely(!in_interrupt() && local_softirq_pending())) {
#if 0
        /*
         * Run softirq if any pending. And do it in its own stack
         * as we may be calling this deep in a task call stack already.
         */
        do_softirq();
#endif
        panic("%s: END!\n", __func__);
    }

    preempt_count_dec();
}

void __raise_softirq_irqoff(unsigned int nr)
{
    or_softirq_pending(1UL << nr);
}

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static void wakeup_softirqd(void)
{
    /* Interrupts are disabled: no need to stop preemption */
    struct task_struct *tsk = __this_cpu_read(ksoftirqd);

    if (tsk)
        wake_up_process(tsk);
}

/*
 * This function must run with irqs disabled!
 */
inline void raise_softirq_irqoff(unsigned int nr)
{
    __raise_softirq_irqoff(nr);

    /*
     * If we're in an interrupt or softirq, we're done
     * (this also catches softirq-disabled code). We will
     * actually run the softirq once we return from
     * the irq or softirq.
     *
     * Otherwise we wake up ksoftirqd to make sure we
     * schedule the softirq soon.
     */
    if (!in_interrupt())
        wakeup_softirqd();
}

void raise_softirq(unsigned int nr)
{
    unsigned long flags;

    local_irq_save(flags);
    raise_softirq_irqoff(nr);
    local_irq_restore(flags);
}
