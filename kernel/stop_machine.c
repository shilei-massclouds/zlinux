// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kernel/stop_machine.c
 *
 * Copyright (C) 2008, 2005 IBM Corporation.
 * Copyright (C) 2008, 2005 Rusty Russell rusty@rustcorp.com.au
 * Copyright (C) 2010       SUSE Linux Products GmbH
 * Copyright (C) 2010       Tejun Heo <tj@kernel.org>
 */
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/stop_machine.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/smpboot.h>
#include <linux/atomic.h>
//#include <linux/nmi.h>
#include <linux/sched/wake_q.h>

/* the actual stopper, one per every possible cpu, enabled on online cpus */
struct cpu_stopper {
    struct task_struct  *thread;

    raw_spinlock_t      lock;
    bool                enabled;    /* is this stopper enabled? */
    struct list_head    works;      /* list of pending works */

    struct cpu_stop_work    stop_work;  /* for stop_cpus */
    unsigned long       caller;
    cpu_stop_fn_t       fn;
};

static DEFINE_PER_CPU(struct cpu_stopper, cpu_stopper);

/* This controls the threads on each CPU. */
enum multi_stop_state {
    /* Dummy starting state for thread. */
    MULTI_STOP_NONE,
    /* Awaiting everyone to be scheduled. */
    MULTI_STOP_PREPARE,
    /* Disable interrupts. */
    MULTI_STOP_DISABLE_IRQ,
    /* Run the function */
    MULTI_STOP_RUN,
    /* Exit */
    MULTI_STOP_EXIT,
};

struct multi_stop_data {
    cpu_stop_fn_t           fn;
    void                    *data;
    /* Like num_online_cpus(), but hotplug cpu uses us, so we need this. */
    unsigned int            num_threads;
    const struct cpumask    *active_cpus;

    enum multi_stop_state   state;
    atomic_t                thread_ack;
};

static bool stop_machine_initialized = false;

static void cpu_stop_park(unsigned int cpu)
{
    struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

    WARN_ON(!list_empty(&stopper->works));
}

static int cpu_stop_should_run(unsigned int cpu)
{
    struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
    unsigned long flags;
    int run;

    raw_spin_lock_irqsave(&stopper->lock, flags);
    run = !list_empty(&stopper->works);
    raw_spin_unlock_irqrestore(&stopper->lock, flags);
    return run;
}

static void cpu_stopper_thread(unsigned int cpu)
{
    panic("%s: NO implementation!\n", __func__);
}

extern void sched_set_stop_task(int cpu, struct task_struct *stop);

static void cpu_stop_create(unsigned int cpu)
{
    sched_set_stop_task(cpu, per_cpu(cpu_stopper.thread, cpu));
}

static struct smp_hotplug_thread cpu_stop_threads = {
    .store              = &cpu_stopper.thread,
    .thread_should_run  = cpu_stop_should_run,
    .thread_fn          = cpu_stopper_thread,
    .thread_comm        = "migration/%u",
    .create             = cpu_stop_create,
    .park               = cpu_stop_park,
    .selfparking        = true,
};

/**
 * stop_one_cpu - stop a cpu
 * @cpu: cpu to stop
 * @fn: function to execute
 * @arg: argument to @fn
 *
 * Execute @fn(@arg) on @cpu.  @fn is run in a process context with
 * the highest priority preempting any task on the cpu and
 * monopolizing it.  This function returns after the execution is
 * complete.
 *
 * This function doesn't guarantee @cpu stays online till @fn
 * completes.  If @cpu goes down in the middle, execution may happen
 * partially or fully on different cpus.  @fn should either be ready
 * for that or the caller should ensure that @cpu stays online until
 * this function completes.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * -ENOENT if @fn(@arg) was not executed because @cpu was offline;
 * otherwise, the return value of @fn.
 */
int stop_one_cpu(unsigned int cpu, cpu_stop_fn_t fn, void *arg)
{
    panic("%s: NO implementation!\n", __func__);
}

int stop_machine_cpuslocked(cpu_stop_fn_t fn, void *data,
                            const struct cpumask *cpus)
{
    struct multi_stop_data msdata = {
        .fn = fn,
        .data = data,
        .num_threads = num_online_cpus(),
        .active_cpus = cpus,
    };

    if (!stop_machine_initialized) {
        /*
         * Handle the case where stop_machine() is called
         * early in boot before stop_machine() has been
         * initialized.
         */
        unsigned long flags;
        int ret;

        WARN_ON_ONCE(msdata.num_threads != 1);

        local_irq_save(flags);
        hard_irq_disable();
        ret = (*fn)(data);
        local_irq_restore(flags);

        return ret;
    }

    panic("%s: NO implementation!\n", __func__);
}

int stop_machine(cpu_stop_fn_t fn, void *data, const struct cpumask *cpus)
{
    int ret;

    /* No CPUs can come up or down during this. */
    cpus_read_lock();
    ret = stop_machine_cpuslocked(fn, data, cpus);
    cpus_read_unlock();
    return ret;
}
EXPORT_SYMBOL_GPL(stop_machine);

void stop_machine_unpark(int cpu)
{
    struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

    stopper->enabled = true;
    kthread_unpark(stopper->thread);
}

static int __init cpu_stop_init(void)
{
    unsigned int cpu;

    for_each_possible_cpu(cpu) {
        struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

        raw_spin_lock_init(&stopper->lock);
        INIT_LIST_HEAD(&stopper->works);
    }

    BUG_ON(smpboot_register_percpu_thread(&cpu_stop_threads));
    stop_machine_unpark(raw_smp_processor_id());
    stop_machine_initialized = true;
    return 0;
}
early_initcall(cpu_stop_init);
