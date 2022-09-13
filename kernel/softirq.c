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
#include <linux/jiffies.h>

#include <asm/softirq_stack.h>

/*
 * We restart softirq processing for at most MAX_SOFTIRQ_RESTART times,
 * but break the loop if need_resched() is set or after 2 ms.
 * The MAX_SOFTIRQ_TIME provides a nice upper bound in most cases, but in
 * certain cases, such as stop_machine(), jiffies may cease to
 * increment and so we need the MAX_SOFTIRQ_RESTART limit as
 * well to make sure we eventually return from this method.
 *
 * These limits have been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
#define MAX_SOFTIRQ_TIME  msecs_to_jiffies(2)
#define MAX_SOFTIRQ_RESTART 10

/*
 * Tasklets
 */
struct tasklet_head {
    struct tasklet_struct *head;
    struct tasklet_struct **tail;
};

static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec);
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec);

DEFINE_PER_CPU_ALIGNED(irq_cpustat_t, irq_stat);
EXPORT_PER_CPU_SYMBOL(irq_stat);

DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

const char * const softirq_to_name[NR_SOFTIRQS] = {
    "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL",
    "TASKLET", "SCHED", "HRTIMER", "RCU"
};

static struct softirq_action softirq_vec[NR_SOFTIRQS]
    __cacheline_aligned_in_smp;

static void tasklet_action_common(struct softirq_action *a,
                                  struct tasklet_head *tl_head,
                                  unsigned int softirq_nr)
{
    panic("%s: END!\n", __func__);
}

static __latent_entropy
void tasklet_action(struct softirq_action *a)
{
    tasklet_action_common(a, this_cpu_ptr(&tasklet_vec),
                          TASKLET_SOFTIRQ);
}

static __latent_entropy
void tasklet_hi_action(struct softirq_action *a)
{
    tasklet_action_common(a, this_cpu_ptr(&tasklet_hi_vec), HI_SOFTIRQ);
}

unsigned int __weak arch_dynirq_lower_bound(unsigned int from)
{
    return from;
}

static void __local_bh_enable(unsigned int cnt)
{
    __preempt_count_sub(cnt);
}

asmlinkage __visible void do_softirq(void)
{
    __u32 pending;
    unsigned long flags;

    if (in_interrupt())
        return;

    panic("%s: END!\n", __func__);
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
        /*
         * Run softirq if any pending. And do it in its own stack
         * as we may be calling this deep in a task call stack already.
         */
        do_softirq();
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

void open_softirq(int nr, void (*action)(struct softirq_action *))
{
    softirq_vec[nr].action = action;
}

/*
 * If ksoftirqd is scheduled, we do not want to process pending softirqs
 * right now. Let ksoftirqd handle this at its own rate, to get fairness,
 * unless we're doing some of the synchronous softirqs.
 */
#define SOFTIRQ_NOW_MASK ((1 << HI_SOFTIRQ) | (1 << TASKLET_SOFTIRQ))
static bool ksoftirqd_running(unsigned long pending)
{
    struct task_struct *tsk = __this_cpu_read(ksoftirqd);

    if (pending & SOFTIRQ_NOW_MASK)
        return false;
    return tsk && task_is_running(tsk) && !__kthread_should_park(tsk);
}

/**
 * irq_enter_rcu - Enter an interrupt context with RCU watching
 */
void irq_enter_rcu(void)
{
    __irq_enter_raw();

#if 0
    if ((is_idle_task(current) && (irq_count() == HARDIRQ_OFFSET)))
        tick_irq_enter();

    account_hardirq_enter(current);
#endif
}

/**
 * irq_enter - Enter an interrupt context including RCU update
 */
void irq_enter(void)
{
    rcu_irq_enter();
    irq_enter_rcu();
}

static inline void invoke_softirq(void)
{
    if (ksoftirqd_running(local_softirq_pending()))
        return;

    if (!force_irqthreads() || !__this_cpu_read(ksoftirqd)) {
        /*
         * Otherwise, irq_exit() is called on the task stack that can
         * be potentially deep already. So call softirq in its own stack
         * to prevent from any overrun.
         */
        do_softirq_own_stack();
    } else {
        wakeup_softirqd();
    }
}

static inline void __irq_exit_rcu(void)
{
    local_irq_disable();
    //account_hardirq_exit(current);
    preempt_count_sub(HARDIRQ_OFFSET);
    if (!in_interrupt() && local_softirq_pending())
        invoke_softirq();

    //tick_irq_exit();
}

/**
 * irq_exit - Exit an interrupt context, update RCU and lockdep
 *
 * Also processes softirqs if needed and possible.
 */
void irq_exit(void)
{
    __irq_exit_rcu();
    rcu_irq_exit();
}

static inline void softirq_handle_begin(void)
{
    __local_bh_disable_ip(_RET_IP_, SOFTIRQ_OFFSET);
}

static inline void softirq_handle_end(void)
{
    __local_bh_enable(SOFTIRQ_OFFSET);
    WARN_ON_ONCE(in_interrupt());
}

asmlinkage __visible void __softirq_entry __do_softirq(void)
{
    //unsigned long end = jiffies + MAX_SOFTIRQ_TIME;
    unsigned long old_flags = current->flags;
    int max_restart = MAX_SOFTIRQ_RESTART;
    struct softirq_action *h;
    bool in_hardirq;
    __u32 pending;
    int softirq_bit;

    /*
     * Mask out PF_MEMALLOC as the current task context is borrowed for the
     * softirq. A softirq handled, such as network RX, might set PF_MEMALLOC
     * again if the socket is related to swapping.
     */
    current->flags &= ~PF_MEMALLOC;

    pending = local_softirq_pending();

    softirq_handle_begin();
    //account_softirq_enter(current);

 restart:
    /* Reset the pending bitmask before enabling irqs */
    set_softirq_pending(0);

    local_irq_enable();

    h = softirq_vec;

    while ((softirq_bit = ffs(pending))) {
        unsigned int vec_nr;
        int prev_count;

        h += softirq_bit - 1;

        vec_nr = h - softirq_vec;
        prev_count = preempt_count();

        kstat_incr_softirqs_this_cpu(vec_nr);

        h->action(h);
        if (unlikely(prev_count != preempt_count())) {
            pr_err("huh, entered softirq %u %s %p with preempt_count %08x, "
                   "exited with %08x?\n",
                   vec_nr, softirq_to_name[vec_nr], h->action,
                   prev_count, preempt_count());
            preempt_count_set(prev_count);
        }

        h++;
        pending >>= softirq_bit;
    }

#if 0
    if (__this_cpu_read(ksoftirqd) == current)
        rcu_softirq_qs();
#endif

    local_irq_disable();

    pending = local_softirq_pending();
#if 0
    if (pending) {
        if (time_before(jiffies, end) && !need_resched() && --max_restart)
            goto restart;

        wakeup_softirqd();
    }
#endif

#if 0
    account_softirq_exit(current);
#endif
    softirq_handle_end();
    current_restore_flags(old_flags, PF_MEMALLOC);
}

void __init softirq_init(void)
{
    int cpu;

    for_each_possible_cpu(cpu) {
        per_cpu(tasklet_vec, cpu).tail =
            &per_cpu(tasklet_vec, cpu).head;
        per_cpu(tasklet_hi_vec, cpu).tail =
            &per_cpu(tasklet_hi_vec, cpu).head;
    }

    open_softirq(TASKLET_SOFTIRQ, tasklet_action);
    open_softirq(HI_SOFTIRQ, tasklet_hi_action);
}
