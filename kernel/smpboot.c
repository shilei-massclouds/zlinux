// SPDX-License-Identifier: GPL-2.0-only
/*
 * Common SMP CPU bringup/teardown functions
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/smp.h>
//#include <linux/delay.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/kthread.h>
#include <linux/smpboot.h>

#include "smpboot.h"

/*
 * For the hotplug case we keep the task structs around and reuse
 * them.
 */
static DEFINE_PER_CPU(struct task_struct *, idle_threads);

static LIST_HEAD(hotplug_threads);
static DEFINE_MUTEX(smpboot_threads_lock);

struct smpboot_thread_data {
    unsigned int cpu;
    unsigned int status;
    struct smp_hotplug_thread   *ht;
};

void __init idle_thread_set_boot_cpu(void)
{
    per_cpu(idle_threads, smp_processor_id()) = current;
}

/**
 * idle_init - Initialize the idle thread for a cpu
 * @cpu:    The cpu for which the idle thread should be initialized
 *
 * Creates the thread if it does not exist.
 */
static __always_inline void idle_init(unsigned int cpu)
{
#if 0
    struct task_struct *tsk = per_cpu(idle_threads, cpu);

    if (!tsk) {
        tsk = fork_idle(cpu);
        if (IS_ERR(tsk))
            pr_err("SMP: fork_idle() failed for CPU %u\n", cpu);
        else
            per_cpu(idle_threads, cpu) = tsk;
    }
#endif
    panic("%s: NO implementation!\n", __func__);
}

/**
 * idle_threads_init - Initialize idle threads for all cpus
 */
void __init idle_threads_init(void)
{
    unsigned int cpu, boot_cpu;

    boot_cpu = smp_processor_id();

    for_each_possible_cpu(cpu) {
        if (cpu != boot_cpu)
            idle_init(cpu);
    }
}

/**
 * smpboot_thread_fn - percpu hotplug thread loop function
 * @data:   thread data pointer
 *
 * Checks for thread stop and park conditions. Calls the necessary
 * setup, cleanup, park and unpark functions for the registered
 * thread.
 *
 * Returns 1 when the thread should exit, 0 otherwise.
 */
static int smpboot_thread_fn(void *data)
{
    panic("%s: NO implementation!\n", __func__);
}

static int
__smpboot_create_thread(struct smp_hotplug_thread *ht, unsigned int cpu)
{
    struct task_struct *tsk = *per_cpu_ptr(ht->store, cpu);
    struct smpboot_thread_data *td;

    if (tsk)
        return 0;

    td = kzalloc_node(sizeof(*td), GFP_KERNEL, cpu_to_node(cpu));
    if (!td)
        return -ENOMEM;
    td->cpu = cpu;
    td->ht = ht;

    tsk = kthread_create_on_cpu(smpboot_thread_fn, td, cpu, ht->thread_comm);

    panic("%s: NO implementation!\n", __func__);
}

/**
 * smpboot_register_percpu_thread - Register a per_cpu thread related
 *                      to hotplug
 * @plug_thread:    Hotplug thread descriptor
 *
 * Creates and starts the threads on all online cpus.
 */
int smpboot_register_percpu_thread(struct smp_hotplug_thread *plug_thread)
{
    unsigned int cpu;
    int ret = 0;

    cpus_read_lock();
    mutex_lock(&smpboot_threads_lock);
    for_each_online_cpu(cpu) {
        ret = __smpboot_create_thread(plug_thread, cpu);
#if 0
        if (ret) {
            smpboot_destroy_threads(plug_thread);
            goto out;
        }
        smpboot_unpark_thread(plug_thread, cpu);
#endif
        panic("%s: 1!\n", __func__);
    }
    list_add(&plug_thread->list, &hotplug_threads);

 out:
    mutex_unlock(&smpboot_threads_lock);
    cpus_read_unlock();
    panic("%s: NO implementation!\n", __func__);
    return ret;
}
EXPORT_SYMBOL_GPL(smpboot_register_percpu_thread);
