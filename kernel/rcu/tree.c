// SPDX-License-Identifier: GPL-2.0+
/*
 * Read-Copy Update mechanism for mutual exclusion (tree-based version)
 *
 * Copyright IBM Corporation, 2008
 *
 * Authors: Dipankar Sarma <dipankar@in.ibm.com>
 *      Manfred Spraul <manfred@colorfullife.com>
 *      Paul E. McKenney <paulmck@linux.ibm.com>
 *
 * Based on the original work by Paul McKenney <paulmck@linux.ibm.com>
 * and inputs from Rusty Russell, Andrea Arcangeli and Andi Kleen.
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 *  Documentation/RCU
 */

#define pr_fmt(fmt) "rcu: " fmt

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
/*
#include <linux/rcupdate_wait.h>
#include <linux/interrupt.h>
*/
#include <linux/sched.h>
#include <linux/sched/debug.h>
//#include <linux/nmi.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/export.h>
/*
#include <linux/completion.h>
#include <linux/moduleparam.h>
#include <linux/panic.h>
#include <linux/panic_notifier.h>
*/
#include <linux/percpu.h>
//#include <linux/notifier.h>
#include <linux/cpu.h>
//#include <linux/mutex.h>
/*
#include <linux/time.h>
#include <linux/wait.h>
*/
#include <linux/kernel_stat.h>
#include <linux/kthread.h>
/*
#include <uapi/linux/sched/types.h>
*/
#include <linux/prefetch.h>
/*
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/trace_events.h>
#include <linux/suspend.h>
#include <linux/ftrace.h>
#include <linux/tick.h>
#include <linux/sysrq.h>
#include <linux/kprobes.h>
*/
#include <linux/gfp.h>
/*
#include <linux/oom.h>
#include <linux/smpboot.h>
*/
#include <linux/jiffies.h>
#include <linux/slab.h>
/*
#include <linux/sched/isolation.h>
#include <linux/sched/clock.h>
#include <linux/vmalloc.h>
*/
#include <linux/mm.h>
//#include "../time/tick-internal.h"

#include "tree.h"
#include "rcu.h"

/*
 * The rcu_scheduler_active variable is initialized to the value
 * RCU_SCHEDULER_INACTIVE and transitions RCU_SCHEDULER_INIT just before the
 * first task is spawned.  So when this variable is RCU_SCHEDULER_INACTIVE,
 * RCU can assume that there is but one task, allowing RCU to (for example)
 * optimize synchronize_rcu() to a simple barrier().  When this variable
 * is RCU_SCHEDULER_INIT, RCU must actually do all the hard work required
 * to detect real grace periods.  This variable is also used to suppress
 * boot-time false positives from lockdep-RCU error checking.  Finally, it
 * transitions from RCU_SCHEDULER_INIT to RCU_SCHEDULER_RUNNING after RCU
 * is fully initialized, including all of its kthreads having been spawned.
 */
int rcu_scheduler_active __read_mostly;
EXPORT_SYMBOL_GPL(rcu_scheduler_active);

/**
 * call_rcu() - Queue an RCU callback for invocation after a grace period.
 * @head: structure to be used for queueing the RCU updates.
 * @func: actual callback function to be invoked after the grace period
 *
 * The callback function will be invoked some time after a full grace
 * period elapses, in other words after all pre-existing RCU read-side
 * critical sections have completed.  However, the callback function
 * might well execute concurrently with RCU read-side critical sections
 * that started after call_rcu() was invoked.
 *
 * RCU read-side critical sections are delimited by rcu_read_lock()
 * and rcu_read_unlock(), and may be nested.  In addition, but only in
 * v5.0 and later, regions of code across which interrupts, preemption,
 * or softirqs have been disabled also serve as RCU read-side critical
 * sections.  This includes hardware interrupt handlers, softirq handlers,
 * and NMI handlers.
 *
 * Note that all CPUs must agree that the grace period extended beyond
 * all pre-existing RCU read-side critical section.  On systems with more
 * than one CPU, this means that when "func()" is invoked, each CPU is
 * guaranteed to have executed a full memory barrier since the end of its
 * last RCU read-side critical section whose beginning preceded the call
 * to call_rcu().  It also means that each CPU executing an RCU read-side
 * critical section that continues beyond the start of "func()" must have
 * executed a memory barrier after the call_rcu() but before the beginning
 * of that RCU read-side critical section.  Note that these guarantees
 * include CPUs that are offline, idle, or executing in user mode, as
 * well as CPUs that are executing in the kernel.
 *
 * Furthermore, if CPU A invoked call_rcu() and CPU B invoked the
 * resulting RCU callback function "func()", then both CPU A and CPU B are
 * guaranteed to execute a full memory barrier during the time interval
 * between the call to call_rcu() and the invocation of "func()" -- even
 * if CPU A and CPU B are the same CPU (but again only if the system has
 * more than one CPU).
 *
 * Implementation of these memory-ordering guarantees is described here:
 * Documentation/RCU/Design/Memory-Ordering/Tree-RCU-Memory-Ordering.rst.
 */
void call_rcu(struct rcu_head *head, rcu_callback_t func)
{
    static atomic_t doublefrees;
    unsigned long flags;
    struct rcu_data *rdp;
    bool was_alldone;

    /* Misaligned rcu_head! */
    WARN_ON_ONCE((unsigned long)head & (sizeof(void *) - 1));

    panic("%s: END\n", __func__);
}
EXPORT_SYMBOL_GPL(call_rcu);

/**
 * synchronize_rcu - wait until a grace period has elapsed.
 *
 * Control will return to the caller some time after a full grace
 * period has elapsed, in other words after all currently executing RCU
 * read-side critical sections have completed.  Note, however, that
 * upon return from synchronize_rcu(), the caller might well be executing
 * concurrently with new RCU read-side critical sections that began while
 * synchronize_rcu() was waiting.
 *
 * RCU read-side critical sections are delimited by rcu_read_lock()
 * and rcu_read_unlock(), and may be nested.  In addition, but only in
 * v5.0 and later, regions of code across which interrupts, preemption,
 * or softirqs have been disabled also serve as RCU read-side critical
 * sections.  This includes hardware interrupt handlers, softirq handlers,
 * and NMI handlers.
 *
 * Note that this guarantee implies further memory-ordering guarantees.
 * On systems with more than one CPU, when synchronize_rcu() returns,
 * each CPU is guaranteed to have executed a full memory barrier since
 * the end of its last RCU read-side critical section whose beginning
 * preceded the call to synchronize_rcu().  In addition, each CPU having
 * an RCU read-side critical section that extends beyond the return from
 * synchronize_rcu() is guaranteed to have executed a full memory barrier
 * after the beginning of synchronize_rcu() and before the beginning of
 * that RCU read-side critical section.  Note that these guarantees include
 * CPUs that are offline, idle, or executing in user mode, as well as CPUs
 * that are executing in the kernel.
 *
 * Furthermore, if CPU A invoked synchronize_rcu(), which returned
 * to its caller on CPU B, then both CPU A and CPU B are guaranteed
 * to have executed a full memory barrier during the execution of
 * synchronize_rcu() -- even if CPU A and CPU B are the same CPU (but
 * again only if the system has more than one CPU).
 *
 * Implementation of these memory-ordering guarantees is described here:
 * Documentation/RCU/Design/Memory-Ordering/Tree-RCU-Memory-Ordering.rst.
 */
void synchronize_rcu(void)
{
    panic("%s: END\n", __func__);
#if 0
    RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map) ||
                     lock_is_held(&rcu_lock_map) ||
                     lock_is_held(&rcu_sched_lock_map),
                     "Illegal synchronize_rcu() in RCU read-side critical section");
    if (rcu_blocking_is_gp())
        return;  // Context allows vacuous grace periods.
    if (rcu_gp_is_expedited())
        synchronize_rcu_expedited();
    else
        wait_rcu_gp(call_rcu);
#endif
}
EXPORT_SYMBOL_GPL(synchronize_rcu);

/*
 * This function is invoked towards the end of the scheduler's
 * initialization process.  Before this is called, the idle task might
 * contain synchronous grace-period primitives (during which time, this idle
 * task is booting the system, and such primitives are no-ops).  After this
 * function is called, any synchronous grace-period primitives are run as
 * expedited, with the requesting task driving the grace period forward.
 * A later core_initcall() rcu_set_runtime_mode() will switch to full
 * runtime RCU functionality.
 */
void rcu_scheduler_starting(void)
{
    WARN_ON(num_online_cpus() != 1);
    WARN_ON(nr_context_switches() > 0);
    rcu_scheduler_active = RCU_SCHEDULER_INIT;
}

/**
 * rcu_irq_enter - inform RCU that current CPU is entering irq away from idle
 *
 * Enter an interrupt handler, which might possibly result in exiting
 * idle mode, in other words, entering the mode in which read-side critical
 * sections can occur.  The caller must have disabled interrupts.
 *
 * Note that the Linux kernel is fully capable of entering an interrupt
 * handler that it never exits, for example when doing upcalls to user mode!
 * This code assumes that the idle loop never does upcalls to user mode.
 * If your architecture's idle loop does do upcalls to user mode (or does
 * anything else that results in unbalanced calls to the irq_enter() and
 * irq_exit() functions), RCU will give you what you deserve, good and hard.
 * But very infrequently and irreproducibly.
 *
 * Use things like work queues to work around this limitation.
 *
 * You have been warned.
 *
 * If you add or remove a call to rcu_irq_enter(), be sure to test with
 * CONFIG_RCU_EQS_DEBUG=y.
 */
noinstr void rcu_irq_enter(void)
{
    //rcu_nmi_enter();
}

/**
 * rcu_irq_exit - inform RCU that current CPU is exiting irq towards idle
 *
 * Exit from an interrupt handler, which might possibly result in entering
 * idle mode, in other words, leaving the mode in which read-side critical
 * sections can occur.  The caller must have disabled interrupts.
 *
 * This code assumes that the idle loop never does anything that might
 * result in unbalanced calls to irq_enter() and irq_exit().  If your
 * architecture's idle loop violates this assumption, RCU will give you what
 * you deserve, good and hard.  But very infrequently and irreproducibly.
 *
 * Use things like work queues to work around this limitation.
 *
 * You have been warned.
 *
 * If you add or remove a call to rcu_irq_exit(), be sure to test with
 * CONFIG_RCU_EQS_DEBUG=y.
 */
void noinstr rcu_irq_exit(void)
{
    //rcu_nmi_exit();
}
