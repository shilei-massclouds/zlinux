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
#include <linux/smpboot.h>
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
    struct completion   done_up;
    struct completion   done_down;
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

static int cpu_up(unsigned int cpu, enum cpuhp_state target)
{
    int err = 0;

    if (!cpu_possible(cpu)) {
        pr_err("can't online cpu %d because it is not configured "
               "as may-hotadd at boot time\n", cpu);
        return -EINVAL;
    }

    panic("%s: END!\n", __func__);
}

void bringup_nonboot_cpus(unsigned int setup_max_cpus)
{
    unsigned int cpu;

    for_each_present_cpu(cpu) {
        if (num_online_cpus() >= setup_max_cpus)
            break;
        if (!cpu_online(cpu))
            cpu_up(cpu, CPUHP_ONLINE);
    }
}

/*
 * The cpu hotplug threads manage the bringup and teardown of the cpus
 */
static void cpuhp_create(unsigned int cpu)
{
    struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);

    init_completion(&st->done_up);
    init_completion(&st->done_down);
}

static int cpuhp_should_run(unsigned int cpu)
{
    struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);

    return st->should_run;
}

/*
 * Execute teardown/startup callbacks on the plugged cpu. Also used to invoke
 * callbacks when a state gets [un]installed at runtime.
 *
 * Each invocation of this function by the smpboot thread does a single AP
 * state callback.
 *
 * It has 3 modes of operation:
 *  - single: runs st->cb_state
 *  - up:     runs ++st->state, while st->state < st->target
 *  - down:   runs st->state--, while st->state > st->target
 *
 * When complete or on error, should_run is cleared and the completion is fired.
 */
static void cpuhp_thread_fun(unsigned int cpu)
{
    panic("%s: END!\n", __func__);
}

static struct smp_hotplug_thread cpuhp_threads = {
    .store              = &cpuhp_state.thread,
    .create             = &cpuhp_create,
    .thread_should_run  = cpuhp_should_run,
    .thread_fn          = cpuhp_thread_fun,
    .thread_comm        = "cpuhp/%u",
    .selfparking        = true,
};

/**
 * struct cpuhp_step - Hotplug state machine step
 * @name:   Name of the step
 * @startup:    Startup function of the step
 * @teardown:   Teardown function of the step
 * @cant_stop:  Bringup/teardown can't be stopped at this step
 * @multi_instance: State has multiple instances which get added afterwards
 */
struct cpuhp_step {
    const char  *name;
    union {
        int     (*single)(unsigned int cpu);
        int     (*multi)(unsigned int cpu, struct hlist_node *node);
    } startup;
    union {
        int     (*single)(unsigned int cpu);
        int     (*multi)(unsigned int cpu, struct hlist_node *node);
    } teardown;
    /* private: */
    struct hlist_head list;
    /* public: */
    bool cant_stop;
    bool multi_instance;
};

static DEFINE_MUTEX(cpuhp_state_mutex);
static struct cpuhp_step cpuhp_hp_states[];

static struct cpuhp_step *cpuhp_get_step(enum cpuhp_state state)
{
    return cpuhp_hp_states + state;
}

static bool cpuhp_step_empty(bool bringup, struct cpuhp_step *step)
{
    return bringup ? !step->startup.single : !step->teardown.single;
}

static bool cpuhp_is_ap_state(enum cpuhp_state state)
{
    /*
     * The extra check for CPUHP_TEARDOWN_CPU is only for documentation
     * purposes as that state is handled explicitly in cpu_down.
     */
    return state > CPUHP_BRINGUP_CPU && state != CPUHP_TEARDOWN_CPU;
}

/**
 * cpuhp_invoke_callback - Invoke the callbacks for a given state
 * @cpu:    The cpu for which the callback should be invoked
 * @state:  The state to do callbacks for
 * @bringup:    True if the bringup callback should be invoked
 * @node:   For multi-instance, do a single entry callback for install/remove
 * @lastp:  For multi-instance rollback, remember how far we got
 *
 * Called from cpu hotplug and from the state register machinery.
 *
 * Return: %0 on success or a negative errno code
 */
static int
cpuhp_invoke_callback(unsigned int cpu, enum cpuhp_state state,
                      bool bringup, struct hlist_node *node,
                      struct hlist_node **lastp)
{
    struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
    struct cpuhp_step *step = cpuhp_get_step(state);
    int (*cbm)(unsigned int cpu, struct hlist_node *node);
    int (*cb)(unsigned int cpu);
    int ret, cnt;

    if (st->fail == state) {
        st->fail = CPUHP_INVALID;
        return -EAGAIN;
    }

    if (cpuhp_step_empty(bringup, step)) {
        WARN_ON_ONCE(1);
        return 0;
    }

    if (!step->multi_instance) {
        WARN_ON_ONCE(lastp && *lastp);
        cb = bringup ? step->startup.single : step->teardown.single;

        ret = cb(cpu);
        return ret;
    }

    panic("%s: END!\n", __func__);
}


/* Invoke a single callback on a remote cpu */
static int
cpuhp_invoke_ap_callback(int cpu, enum cpuhp_state state, bool bringup,
                         struct hlist_node *node)
{
    struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
    int ret;

    if (!cpu_online(cpu))
        return 0;

    /*
     * If we are up and running, use the hotplug thread. For early calls
     * we invoke the thread function directly.
     */
    if (!st->thread)
        return cpuhp_invoke_callback(cpu, state, bringup, node, NULL);

    panic("%s: END!\n", __func__);
}

/* Sanity check for callbacks */
static int cpuhp_cb_check(enum cpuhp_state state)
{
    if (state <= CPUHP_OFFLINE || state >= CPUHP_ONLINE)
        return -EINVAL;
    return 0;
}

static int cpuhp_store_callbacks(enum cpuhp_state state, const char *name,
                                 int (*startup)(unsigned int cpu),
                                 int (*teardown)(unsigned int cpu),
                                 bool multi_instance)
{
    /* (Un)Install the callbacks for further cpu hotplug operations */
    struct cpuhp_step *sp;
    int ret = 0;

    /*
     * If name is NULL, then the state gets removed.
     *
     * CPUHP_AP_ONLINE_DYN and CPUHP_BP_PREPARE_DYN are handed out on
     * the first allocation from these dynamic ranges, so the removal
     * would trigger a new allocation and clear the wrong (already
     * empty) state, leaving the callbacks of the to be cleared state
     * dangling, which causes wreckage on the next hotplug operation.
     */
    if (name && (state == CPUHP_AP_ONLINE_DYN ||
                 state == CPUHP_BP_PREPARE_DYN)) {
#if 0
        ret = cpuhp_reserve_state(state);
        if (ret < 0)
            return ret;
        state = ret;
#endif
        panic("%s: DYN!\n", __func__);
    }
    sp = cpuhp_get_step(state);
    if (name && sp->name)
        return -EBUSY;

    sp->startup.single = startup;
    sp->teardown.single = teardown;
    sp->name = name;
    sp->multi_instance = multi_instance;
    INIT_HLIST_HEAD(&sp->list);
    return ret;
}

/*
 * Call the startup/teardown function for a step either on the AP or
 * on the current CPU.
 */
static int cpuhp_issue_call(int cpu, enum cpuhp_state state, bool bringup,
                            struct hlist_node *node)
{
    struct cpuhp_step *sp = cpuhp_get_step(state);
    int ret;

    /*
     * If there's nothing to do, we done.
     * Relies on the union for multi_instance.
     */
    if (cpuhp_step_empty(bringup, sp))
        return 0;

    /*
     * The non AP bound callbacks can fail on bringup. On teardown
     * e.g. module removal we crash for now.
     */
    if (cpuhp_is_ap_state(state))
        ret = cpuhp_invoke_ap_callback(cpu, state, bringup, node);
    else
        ret = cpuhp_invoke_callback(cpu, state, bringup, node, NULL);

    BUG_ON(ret && !bringup);
    return ret;
}

/**
 * __cpuhp_setup_state_cpuslocked - Setup the callbacks for an hotplug machine state
 * @state:      The state to setup
 * @name:       Name of the step
 * @invoke:     If true, the startup function is invoked for cpus where
 *          cpu state >= @state
 * @startup:        startup callback function
 * @teardown:       teardown callback function
 * @multi_instance: State is set up for multiple instances which get
 *          added afterwards.
 *
 * The caller needs to hold cpus read locked while calling this function.
 * Return:
 *   On success:
 *      Positive state number if @state is CPUHP_AP_ONLINE_DYN;
 *      0 for all other states
 *   On failure: proper (negative) error code
 */
int __cpuhp_setup_state_cpuslocked(enum cpuhp_state state,
                                   const char *name, bool invoke,
                                   int (*startup)(unsigned int cpu),
                                   int (*teardown)(unsigned int cpu),
                                   bool multi_instance)
{
    int cpu, ret = 0;
    bool dynstate;

    if (cpuhp_cb_check(state) || !name)
        return -EINVAL;

    mutex_lock(&cpuhp_state_mutex);

    ret = cpuhp_store_callbacks(state, name, startup, teardown, multi_instance);

    dynstate = state == CPUHP_AP_ONLINE_DYN;
    if (ret > 0 && dynstate) {
        state = ret;
        ret = 0;
    }

    if (ret || !invoke || !startup)
        goto out;

    /*
     * Try to call the startup callback for each present cpu
     * depending on the hotplug state of the cpu.
     */
    for_each_present_cpu(cpu) {
        struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
        int cpustate = st->state;

        if (cpustate < state)
            continue;

        ret = cpuhp_issue_call(cpu, state, true, NULL);
        if (ret) {
#if 0
            if (teardown)
                cpuhp_rollback_install(cpu, state, NULL);
            cpuhp_store_callbacks(state, NULL, NULL, NULL, false);
            goto out;
#endif
            panic("%s: cpuhp_issue_call error!\n", __func__);
        }
    }

 out:
    mutex_unlock(&cpuhp_state_mutex);
    /*
     * If the requested state is CPUHP_AP_ONLINE_DYN, return the
     * dynamically allocated state in case of success.
     */
    if (!ret && dynstate)
        return state;
    return ret;
}

int __cpuhp_setup_state(enum cpuhp_state state,
                        const char *name, bool invoke,
                        int (*startup)(unsigned int cpu),
                        int (*teardown)(unsigned int cpu),
                        bool multi_instance)
{
    int ret;

    cpus_read_lock();
    ret = __cpuhp_setup_state_cpuslocked(state, name, invoke, startup,
                                         teardown, multi_instance);
    cpus_read_unlock();
    return ret;
}
EXPORT_SYMBOL(__cpuhp_setup_state);

void __init cpuhp_threads_init(void)
{
    //BUG_ON(smpboot_register_percpu_thread(&cpuhp_threads));
    //kthread_unpark(this_cpu_read(cpuhp_state.thread));
    panic("%s: END!\n", __func__);
}

/* Boot processor state steps */
static struct cpuhp_step cpuhp_hp_states[] = {
    [CPUHP_OFFLINE] = {
        .name           = "offline",
        .startup.single     = NULL,
        .teardown.single    = NULL,
    },
    [CPUHP_CREATE_THREADS]= {
        .name           = "threads:prepare",
        //.startup.single     = smpboot_create_threads,
        .teardown.single    = NULL,
        .cant_stop      = true,
    },
    [CPUHP_PERF_PREPARE] = {
        .name           = "perf:prepare",
#if 0
        .startup.single     = perf_event_init_cpu,
        .teardown.single    = perf_event_exit_cpu,
#endif
    },
    [CPUHP_RANDOM_PREPARE] = {
        .name           = "random:prepare",
        //.startup.single     = random_prepare_cpu,
        .teardown.single    = NULL,
    },
    [CPUHP_WORKQUEUE_PREP] = {
        .name           = "workqueue:prepare",
#if 0
        .startup.single     = workqueue_prepare_cpu,
        .teardown.single    = NULL,
#endif
    },
    [CPUHP_HRTIMERS_PREPARE] = {
        .name           = "hrtimers:prepare",
#if 0
        .startup.single     = hrtimers_prepare_cpu,
        .teardown.single    = hrtimers_dead_cpu,
#endif
    },
    [CPUHP_SMPCFD_PREPARE] = {
        .name           = "smpcfd:prepare",
#if 0
        .startup.single     = smpcfd_prepare_cpu,
        .teardown.single    = smpcfd_dead_cpu,
#endif
    },
    [CPUHP_RELAY_PREPARE] = {
        .name           = "relay:prepare",
#if 0
        .startup.single     = relay_prepare_cpu,
        .teardown.single    = NULL,
#endif
    },
    [CPUHP_SLAB_PREPARE] = {
        .name           = "slab:prepare",
#if 0
        .startup.single     = slab_prepare_cpu,
        .teardown.single    = slab_dead_cpu,
#endif
    },
    [CPUHP_RCUTREE_PREP] = {
        .name           = "RCU/tree:prepare",
#if 0
        .startup.single     = rcutree_prepare_cpu,
        .teardown.single    = rcutree_dead_cpu,
#endif
    },
    /*
     * On the tear-down path, timers_dead_cpu() must be invoked
     * before blk_mq_queue_reinit_notify() from notify_dead(),
     * otherwise a RCU stall occurs.
     */
    [CPUHP_TIMERS_PREPARE] = {
        .name           = "timers:prepare",
#if 0
        .startup.single     = timers_prepare_cpu,
        .teardown.single    = timers_dead_cpu,
#endif
    },
    /* Kicks the plugged cpu into life */
    [CPUHP_BRINGUP_CPU] = {
        .name           = "cpu:bringup",
#if 0
        .startup.single     = bringup_cpu,
        .teardown.single    = finish_cpu,
#endif
        .cant_stop      = true,
    },
    /* Final state before CPU kills itself */
    [CPUHP_AP_IDLE_DEAD] = {
        .name           = "idle:dead",
    },
    /*
     * Last state before CPU enters the idle loop to die. Transient state
     * for synchronization.
     */
    [CPUHP_AP_OFFLINE] = {
        .name           = "ap:offline",
        .cant_stop      = true,
    },
    /* First state is scheduler control. Interrupts are disabled */
    [CPUHP_AP_SCHED_STARTING] = {
        .name           = "sched:starting",
#if 0
        .startup.single     = sched_cpu_starting,
        .teardown.single    = sched_cpu_dying,
#endif
    },
    [CPUHP_AP_RCUTREE_DYING] = {
        .name           = "RCU/tree:dying",
#if 0
        .startup.single     = NULL,
        .teardown.single    = rcutree_dying_cpu,
#endif
    },
    [CPUHP_AP_SMPCFD_DYING] = {
        .name           = "smpcfd:dying",
        .startup.single     = NULL,
        //.teardown.single    = smpcfd_dying_cpu,
    },
    /* Entry state on starting. Interrupts enabled from here on. Transient
     * state for synchronsization */
    [CPUHP_AP_ONLINE] = {
        .name           = "ap:online",
    },
    /*
     * Handled on control processor until the plugged processor manages
     * this itself.
     */
    [CPUHP_TEARDOWN_CPU] = {
        .name           = "cpu:teardown",
        .startup.single     = NULL,
        //.teardown.single    = takedown_cpu,
        .cant_stop      = true,
    },
    [CPUHP_AP_SCHED_WAIT_EMPTY] = {
        .name           = "sched:waitempty",
        .startup.single     = NULL,
        //.teardown.single    = sched_cpu_wait_empty,
    },

    /* Handle smpboot threads park/unpark */
    [CPUHP_AP_SMPBOOT_THREADS] = {
        .name           = "smpboot/threads:online",
#if 0
        .startup.single     = smpboot_unpark_threads,
        .teardown.single    = smpboot_park_threads,
#endif
    },
    [CPUHP_AP_IRQ_AFFINITY_ONLINE] = {
        .name           = "irq/affinity:online",
        //.startup.single     = irq_affinity_online_cpu,
        .teardown.single    = NULL,
    },
    [CPUHP_AP_PERF_ONLINE] = {
        .name           = "perf:online",
#if 0
        .startup.single     = perf_event_init_cpu,
        .teardown.single    = perf_event_exit_cpu,
#endif
    },
    [CPUHP_AP_WATCHDOG_ONLINE] = {
        .name           = "lockup_detector:online",
#if 0
        .startup.single     = lockup_detector_online_cpu,
        .teardown.single    = lockup_detector_offline_cpu,
#endif
    },
    [CPUHP_AP_WORKQUEUE_ONLINE] = {
        .name           = "workqueue:online",
#if 0
        .startup.single     = workqueue_online_cpu,
        .teardown.single    = workqueue_offline_cpu,
#endif
    },
    [CPUHP_AP_RANDOM_ONLINE] = {
        .name           = "random:online",
#if 0
        .startup.single     = random_online_cpu,
        .teardown.single    = NULL,
#endif
    },
    [CPUHP_AP_RCUTREE_ONLINE] = {
        .name           = "RCU/tree:online",
#if 0
        .startup.single     = rcutree_online_cpu,
        .teardown.single    = rcutree_offline_cpu,
#endif
    },
    /*
     * The dynamically registered state space is here
     */
    /* Last state is scheduler control setting the cpu active */
    [CPUHP_AP_ACTIVE] = {
        .name           = "sched:active",
#if 0
        .startup.single     = sched_cpu_activate,
        .teardown.single    = sched_cpu_deactivate,
#endif
    },

    /* CPU is fully up and running. */
    [CPUHP_ONLINE] = {
        .name           = "online",
        .startup.single     = NULL,
        .teardown.single    = NULL,
    },
};
