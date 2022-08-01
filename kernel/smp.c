// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic helpers for smp ipi calls
 *
 * (C) Jens Axboe <jens.axboe@oracle.com> 2008
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/*
#include <linux/irq_work.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
*/
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/init.h>
//#include <linux/interrupt.h>
#include <linux/gfp.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/sched.h>
/*
#include <linux/sched/idle.h>
#include <linux/hypervisor.h>
#include <linux/sched/clock.h>
#include <linux/nmi.h>
*/
#include <linux/sched/debug.h>
#include <linux/jump_label.h>

#include "smpboot.h"
//#include "sched/smp.h"

/* Setup number of possible processor ids */
unsigned int nr_cpu_ids __read_mostly = NR_CPUS;
EXPORT_SYMBOL(nr_cpu_ids);

/* Setup configured maximum number of CPUs to activate */
unsigned int setup_max_cpus = NR_CPUS;
EXPORT_SYMBOL(setup_max_cpus);

/**
 * smp_call_function_many(): Run a function on a set of CPUs.
 * @mask: The set of cpus to run on (only runs on online subset).
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: Bitmask that controls the operation. If %SCF_WAIT is set, wait
 *        (atomically) until function has completed on other CPUs. If
 *        %SCF_RUN_LOCAL is set, the function will also be run locally
 *        if the local CPU is set in the @cpumask.
 *
 * If @wait is true, then returns once @func has returned.
 *
 * You must not call this function with disabled interrupts or from a
 * hardware interrupt handler or from a bottom half handler. Preemption
 * must be disabled when calling this function.
 */
void smp_call_function_many(const struct cpumask *mask,
                            smp_call_func_t func, void *info, bool wait)
{
    panic("%s: NO implementation!\n", __func__);
    //smp_call_function_many_cond(mask, func, info, wait * SCF_WAIT, NULL);
}
EXPORT_SYMBOL(smp_call_function_many);

/**
 * smp_call_function(): Run a function on all other CPUs.
 * @func: The function to run. This must be fast and non-blocking.
 * @info: An arbitrary pointer to pass to the function.
 * @wait: If true, wait (atomically) until function has completed
 *        on other CPUs.
 *
 * Returns 0.
 *
 * If @wait is true, then returns once @func has returned; otherwise
 * it returns just before the target cpu calls @func.
 *
 * You must not call this function with disabled interrupts or from a
 * hardware interrupt handler or from a bottom half handler.
 */
void smp_call_function(smp_call_func_t func, void *info, int wait)
{
    preempt_disable();
    smp_call_function_many(cpu_online_mask, func, info, wait);
    preempt_enable();
}
EXPORT_SYMBOL(smp_call_function);

static void do_nothing(void *unused)
{
}

/**
 * kick_all_cpus_sync - Force all cpus out of idle
 *
 * Used to synchronize the update of pm_idle function pointer. It's
 * called after the pointer is updated and returns after the dummy
 * callback function has been executed on all cpus. The execution of
 * the function can only happen on the remote cpus after they have
 * left the idle function which had been called via pm_idle function
 * pointer. So it's guaranteed that nothing uses the previous pointer
 * anymore.
 */
void kick_all_cpus_sync(void)
{
    /* Make sure the change is visible before we kick the cpus */
    smp_mb();
    smp_call_function(do_nothing, NULL, 1);
}
EXPORT_SYMBOL_GPL(kick_all_cpus_sync);

/* An arch may set nr_cpu_ids earlier if needed, so this would be redundant */
void __init setup_nr_cpu_ids(void)
{
    nr_cpu_ids = find_last_bit(cpumask_bits(cpu_possible_mask), NR_CPUS) + 1;
}

/* Called by boot processor to activate the rest. */
void __init smp_init(void)
{
    int num_nodes, num_cpus;

    idle_threads_init();
#if 0
    cpuhp_threads_init();
#endif

    pr_info("Bringing up secondary CPUs ...\n");

    bringup_nonboot_cpus(setup_max_cpus);

    num_nodes = num_online_nodes();
    num_cpus  = num_online_cpus();
    pr_info("Brought up %d node%s, %d CPU%s\n",
            num_nodes, (num_nodes > 1 ? "s" : ""),
            num_cpus,  (num_cpus  > 1 ? "s" : ""));
}
