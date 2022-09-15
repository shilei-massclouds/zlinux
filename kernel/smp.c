// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic helpers for smp ipi calls
 *
 * (C) Jens Axboe <jens.axboe@oracle.com> 2008
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/irq_work.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
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

/*
 * Flags to be used as scf_flags argument of smp_call_function_many_cond().
 *
 * %SCF_WAIT:       Wait until function execution is completed
 * %SCF_RUN_LOCAL:  Run also locally if local cpu is set in cpumask
 */
#define SCF_WAIT        (1U << 0)
#define SCF_RUN_LOCAL   (1U << 1)

static DEFINE_PER_CPU_SHARED_ALIGNED(struct llist_head,
                                     call_single_queue);

static void smp_call_function_many_cond(const struct cpumask *mask,
                                        smp_call_func_t func, void *info,
                                        unsigned int scf_flags,
                                        smp_cond_func_t cond_func)
{
    int cpu, last_cpu, this_cpu = smp_processor_id();
    struct call_function_data *cfd;
    bool wait = scf_flags & SCF_WAIT;
    bool run_remote = false;
    bool run_local = false;
    int nr_cpus = 0;

    /*
     * When @wait we can deadlock when we interrupt between llist_add() and
     * arch_send_call_function_ipi*(); when !@wait we can deadlock due to
     * csd_lock() on because the interrupt context uses the same csd
     * storage.
     */
    WARN_ON_ONCE(!in_task());

    /* Check if we need local execution. */
    if ((scf_flags & SCF_RUN_LOCAL) && cpumask_test_cpu(this_cpu, mask))
        run_local = true;

    /* Check if we need remote execution, i.e., any CPU excluding this one. */
    cpu = cpumask_first_and(mask, cpu_online_mask);
    if (cpu == this_cpu)
        cpu = cpumask_next_and(cpu, mask, cpu_online_mask);
    if (cpu < nr_cpu_ids)
        run_remote = true;

    if (run_remote) {
        panic("%s: run_remote!\n", __func__);
    }

    if (run_local && (!cond_func || cond_func(this_cpu, info))) {
        unsigned long flags;

        local_irq_save(flags);
        func(info);
        local_irq_restore(flags);
    }

    if (run_remote && wait) {
        panic("%s: run_remote && wait!\n", __func__);
    }
}

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

/*
 * on_each_cpu_cond(): Call a function on each processor for which
 * the supplied function cond_func returns true, optionally waiting
 * for all the required CPUs to finish. This may include the local
 * processor.
 * @cond_func:  A callback function that is passed a cpu id and
 *      the info parameter. The function is called
 *      with preemption disabled. The function should
 *      return a blooean value indicating whether to IPI
 *      the specified CPU.
 * @func:   The function to run on all applicable CPUs.
 *      This must be fast and non-blocking.
 * @info:   An arbitrary pointer to pass to both functions.
 * @wait:   If true, wait (atomically) until function has
 *      completed on other CPUs.
 *
 * Preemption is disabled to protect against CPUs going offline but not online.
 * CPUs going online during the call will not be seen or sent an IPI.
 *
 * You must not call this function with disabled interrupts or
 * from a hardware interrupt handler or from a bottom half handler.
 */
void on_each_cpu_cond_mask(smp_cond_func_t cond_func, smp_call_func_t func,
                           void *info, bool wait, const struct cpumask *mask)
{
    unsigned int scf_flags = SCF_RUN_LOCAL;

    if (wait)
        scf_flags |= SCF_WAIT;

    preempt_disable();
    smp_call_function_many_cond(mask, func, info, scf_flags, cond_func);
    preempt_enable();
}

void flush_smp_call_function_from_idle(void)
{
    unsigned long flags;

    if (llist_empty(this_cpu_ptr(&call_single_queue)))
        return;

    panic("%s: END!\n", __func__);
}

/* Called by boot processor to activate the rest. */
void __init smp_init(void)
{
    int num_nodes, num_cpus;

    idle_threads_init();
    cpuhp_threads_init();

    pr_info("Bringing up secondary CPUs ...\n");

    bringup_nonboot_cpus(setup_max_cpus);

    num_nodes = num_online_nodes();
    num_cpus  = num_online_cpus();
    pr_info("Brought up %d node%s, %d CPU%s\n",
            num_nodes, (num_nodes > 1 ? "s" : ""),
            num_cpus,  (num_cpus  > 1 ? "s" : ""));
}
