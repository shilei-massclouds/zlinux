/* CPU control.
 * (C) 2001, 2002, 2003, 2004 Rusty Russell
 *
 * This code is licenced under the GPL.
 */

#include <linux/sched/mm.h>
//#include <linux/proc_fs.h>
#include <linux/smp.h>
#include <linux/init.h>
//#include <linux/notifier.h>
#include <linux/sched/signal.h>
#if 0
#include <linux/sched/hotplug.h>
#include <linux/sched/isolation.h>
#include <linux/sched/task.h>
#include <linux/sched/smt.h>
#include <linux/unistd.h>
#endif
#include <linux/cpu.h>
//#include <linux/oom.h>
#include <linux/rcupdate.h>
#include <linux/export.h>
#include <linux/bug.h>
#include <linux/kthread.h>
//#include <linux/stop_machine.h>
#include <linux/mutex.h>
#include <linux/gfp.h>
//#include <linux/suspend.h>
#include <linux/lockdep.h>
//#include <linux/tick.h>
#include <linux/irq.h>
//#include <linux/nmi.h>
//#include <linux/smpboot.h>
//#include <linux/relay.h>
#include <linux/slab.h>
//#include <linux/scs.h>
#include <linux/percpu-rwsem.h>
#if 0
#include <linux/cpuset.h>
#include <linux/random.h>

#include "smpboot.h"
#endif

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

/*
 * cpu_bit_bitmap[] is a special, "compressed" data structure that
 * represents all NR_CPUS bits binary values of 1<<nr.
 *
 * It is used by cpumask_of() to get a constant address to a CPU
 * mask value that has a single bit set only.
 */

/* cpu_bit_bitmap[0] is empty - so we can back into it */
#define MASK_DECLARE_1(x)   [x+1][0] = (1UL << (x))
#define MASK_DECLARE_2(x)   MASK_DECLARE_1(x), MASK_DECLARE_1(x+1)
#define MASK_DECLARE_4(x)   MASK_DECLARE_2(x), MASK_DECLARE_2(x+2)
#define MASK_DECLARE_8(x)   MASK_DECLARE_4(x), MASK_DECLARE_4(x+4)

const unsigned long cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)] = {
    MASK_DECLARE_8(0),  MASK_DECLARE_8(8),
    MASK_DECLARE_8(16), MASK_DECLARE_8(24),
    MASK_DECLARE_8(32), MASK_DECLARE_8(40),
    MASK_DECLARE_8(48), MASK_DECLARE_8(56),
};
EXPORT_SYMBOL_GPL(cpu_bit_bitmap);

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

DEFINE_STATIC_PERCPU_RWSEM(cpu_hotplug_lock);

void cpus_read_lock(void)
{
    percpu_down_read(&cpu_hotplug_lock);
}
EXPORT_SYMBOL_GPL(cpus_read_lock);

int cpus_read_trylock(void)
{
    return percpu_down_read_trylock(&cpu_hotplug_lock);
}
EXPORT_SYMBOL_GPL(cpus_read_trylock);

void cpus_read_unlock(void)
{
    percpu_up_read(&cpu_hotplug_lock);
}
EXPORT_SYMBOL_GPL(cpus_read_unlock);

void cpus_write_lock(void)
{
    percpu_down_write(&cpu_hotplug_lock);
}

void cpus_write_unlock(void)
{
    percpu_up_write(&cpu_hotplug_lock);
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
