/* CPU control.
 * (C) 2001, 2002, 2003, 2004 Rusty Russell
 *
 * This code is licenced under the GPL.
 */

#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/bug.h>

int __boot_cpu_id;

struct cpumask __cpu_possible_mask __read_mostly;
EXPORT_SYMBOL(__cpu_possible_mask);

struct cpumask __cpu_online_mask __read_mostly;
EXPORT_SYMBOL(__cpu_online_mask);

struct cpumask __cpu_present_mask __read_mostly;
EXPORT_SYMBOL(__cpu_present_mask);

struct cpumask __cpu_active_mask __read_mostly;
EXPORT_SYMBOL(__cpu_active_mask);

atomic_t __num_online_cpus __read_mostly;
EXPORT_SYMBOL(__num_online_cpus);

void set_cpu_online(unsigned int cpu, bool online)
{
    /*
     * atomic_inc/dec() is required to handle the horrid abuse of this
     * function by the reboot and kexec code which invoke it from
     * IPI/NMI broadcasts when shutting down CPUs. Invocation from
     * regular CPU hotplug is properly serialized.
     *
     * Note, that the fact that __num_online_cpus is of type atomic_t
     * does not protect readers which are not serialized against
     * concurrent hotplug operations.
     */
    if (online) {
        if (!cpumask_test_and_set_cpu(cpu, &__cpu_online_mask))
            atomic_inc(&__num_online_cpus);
    } else {
        if (cpumask_test_and_clear_cpu(cpu, &__cpu_online_mask))
            atomic_dec(&__num_online_cpus);
    }
}

/*
 * Activate the first processor.
 */
void __init boot_cpu_init(void)
{
    int cpu = smp_processor_id();

    /* Mark the boot cpu "present", "online" etc for SMP and UP case */
    set_cpu_online(cpu, true);
    set_cpu_active(cpu, true);
    set_cpu_present(cpu, true);
    set_cpu_possible(cpu, true);

    __boot_cpu_id = cpu;
}
