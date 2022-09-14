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

/* Data structures. */

static DEFINE_PER_CPU_SHARED_ALIGNED(struct rcu_data, rcu_data) = {
    .dynticks_nesting = 1,
    .dynticks_nmi_nesting = DYNTICK_IRQ_NONIDLE,
    .dynticks = ATOMIC_INIT(1),
};

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

/*
 * Increment the current CPU's rcu_data structure's ->dynticks field
 * with ordering.  Return the new value.
 */
static noinline noinstr unsigned long rcu_dynticks_inc(int incby)
{
    return arch_atomic_add_return(incby,
                                  this_cpu_ptr(&rcu_data.dynticks));
}

/*
 * Record entry into an extended quiescent state.  This is only to be
 * called when not already in an extended quiescent state, that is,
 * RCU is watching prior to the call to this function and is no longer
 * watching upon return.
 */
static noinstr void rcu_dynticks_eqs_enter(void)
{
    int seq;

    /*
     * CPUs seeing atomic_add_return() must see prior RCU read-side
     * critical sections, and we also must force ordering with the
     * next idle sojourn.
     */
    seq = rcu_dynticks_inc(1);
}

/*
 * Record exit from an extended quiescent state.  This is only to be
 * called from an extended quiescent state, that is, RCU is not watching
 * prior to the call to this function and is watching upon return.
 */
static noinstr void rcu_dynticks_eqs_exit(void)
{
    int seq;

    /*
     * CPUs seeing atomic_add_return() must see prior idle sojourns,
     * and we also must force ordering with the next RCU read-side
     * critical section.
     */
    seq = rcu_dynticks_inc(1);
}

/*
 * Enter an RCU extended quiescent state, which can be either the
 * idle loop or adaptive-tickless usermode execution.
 *
 * We crowbar the ->dynticks_nmi_nesting field to zero to allow for
 * the possibility of usermode upcalls having messed up our count
 * of interrupt nesting level during the prior busy period.
 */
static noinstr void rcu_eqs_enter(bool user)
{
    struct rcu_data *rdp = this_cpu_ptr(&rcu_data);

    WARN_ON_ONCE(rdp->dynticks_nmi_nesting != DYNTICK_IRQ_NONIDLE);
    WRITE_ONCE(rdp->dynticks_nmi_nesting, 0);
    if (rdp->dynticks_nesting != 1) {
        // RCU will still be watching, so just do accounting and leave.
        rdp->dynticks_nesting--;
        return;
    }

    instrumentation_begin();
    rcu_preempt_deferred_qs(current);
    instrumentation_end();

    WRITE_ONCE(rdp->dynticks_nesting, 0); /* Avoid irq-access tearing. */
    // RCU is watching here ...
    rcu_dynticks_eqs_enter();
    // ... but is no longer watching here.
    rcu_dynticks_task_enter();
}

/*
 * Exit an RCU extended quiescent state, which can be either the
 * idle loop or adaptive-tickless usermode execution.
 *
 * We crowbar the ->dynticks_nmi_nesting field to DYNTICK_IRQ_NONIDLE to
 * allow for the possibility of usermode upcalls messing up our count of
 * interrupt nesting level during the busy period that is just now starting.
 */
static void noinstr rcu_eqs_exit(bool user)
{
    struct rcu_data *rdp;
    long oldval;

    rdp = this_cpu_ptr(&rcu_data);
    oldval = rdp->dynticks_nesting;
    if (oldval) {
        // RCU was already watching, so just do accounting and leave.
        rdp->dynticks_nesting++;
        return;
    }
    rcu_dynticks_task_exit();
    // RCU is not watching here ...
    rcu_dynticks_eqs_exit();
    // ... but is watching here.
    instrumentation_begin();
    WRITE_ONCE(rdp->dynticks_nesting, 1);
    WARN_ON_ONCE(rdp->dynticks_nmi_nesting);
    WRITE_ONCE(rdp->dynticks_nmi_nesting, DYNTICK_IRQ_NONIDLE);
    instrumentation_end();
}

/**
 * rcu_idle_enter - inform RCU that current CPU is entering idle
 *
 * Enter idle mode, in other words, -leave- the mode in which RCU
 * read-side critical sections can occur.  (Though RCU read-side
 * critical sections can occur in irq handlers in idle, a possibility
 * handled by irq_enter() and irq_exit().)
 *
 * If you add or remove a call to rcu_idle_enter(), be sure to test with
 * CONFIG_RCU_EQS_DEBUG=y.
 */
void rcu_idle_enter(void)
{
    rcu_eqs_enter(false);
}
EXPORT_SYMBOL_GPL(rcu_idle_enter);

/**
 * rcu_idle_exit - inform RCU that current CPU is leaving idle
 *
 * Exit idle mode, in other words, -enter- the mode in which RCU
 * read-side critical sections can occur.
 *
 * If you add or remove a call to rcu_idle_exit(), be sure to test with
 * CONFIG_RCU_EQS_DEBUG=y.
 */
void rcu_idle_exit(void)
{
    unsigned long flags;

    local_irq_save(flags);
    rcu_eqs_exit(false);
    local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(rcu_idle_exit);

#if 0
#include "tree_stall.h"
#include "tree_exp.h"
#include "tree_nocb.h"
#endif
#include "tree_plugin.h"
