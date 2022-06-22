/* CPU control.
 * (C) 2001, 2002, 2003, 2004 Rusty Russell
 *
 * This code is licenced under the GPL.
 */

#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/bug.h>
#include <linux/percpu.h>

/**
 * struct cpuhp_cpu_state - Per cpu hotplug state storage
 * @state:  The current cpu state
 * @target: The target state
 * @fail:   Current CPU hotplug callback state
 * @thread: Pointer to the hotplug thread
 * @should_run: Thread should execute
 * @rollback:   Perform a rollback
 * @single: Single callback invocation
 * @bringup:    Single callback bringup or teardown selector
 * @cpu:    CPU number
 * @node:   Remote CPU node; for multi-instance, do a
 *      single entry callback for install/remove
 * @last:   For multi-instance rollback, remember how far we got
 * @cb_state:   The state for a single callback (install/uninstall)
 * @result: Result of the operation
 * @done_up:    Signal completion to the issuer of the task for cpu-up
 * @done_down:  Signal completion to the issuer of the task for cpu-down
 */
struct cpuhp_cpu_state {
    enum cpuhp_state    state;
    enum cpuhp_state    target;
    enum cpuhp_state    fail;
    struct task_struct  *thread;
    bool            should_run;
    bool            rollback;
    bool            single;
    bool            bringup;
    struct hlist_node   *node;
    struct hlist_node   *last;
    enum cpuhp_state    cb_state;
    int         result;
#if 0
    struct completion   done_up;
    struct completion   done_down;
#endif
};

static DEFINE_PER_CPU(struct cpuhp_cpu_state, cpuhp_state) = {
    .fail = CPUHP_INVALID,
};

int __boot_cpu_id;

struct cpumask __cpu_possible_mask __read_mostly;
EXPORT_SYMBOL(__cpu_possible_mask);

struct cpumask __cpu_online_mask __read_mostly;
EXPORT_SYMBOL(__cpu_online_mask);

struct cpumask __cpu_present_mask __read_mostly;
EXPORT_SYMBOL(__cpu_present_mask);

struct cpumask __cpu_active_mask __read_mostly;
EXPORT_SYMBOL(__cpu_active_mask);

struct cpumask __cpu_dying_mask __read_mostly;
EXPORT_SYMBOL(__cpu_dying_mask);

atomic_t __num_online_cpus __read_mostly;
EXPORT_SYMBOL(__num_online_cpus);

cpumask_t cpus_booted_once_mask;

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

/*
 * Must be called _AFTER_ setting up the per_cpu areas
 */
void __init boot_cpu_hotplug_init(void)
{
    cpumask_set_cpu(smp_processor_id(), &cpus_booted_once_mask);
    this_cpu_write(cpuhp_state.state, CPUHP_ONLINE);
}
