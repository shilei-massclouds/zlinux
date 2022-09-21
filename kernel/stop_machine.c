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
#include <linux/nmi.h>
#include <linux/sched/wake_q.h>

/*
 * Structure to determine completion condition and record errors.  May
 * be shared by works on different cpus.
 */
struct cpu_stop_done {
    atomic_t        nr_todo;    /* nr left to execute */
    int             ret;        /* collected return value */
    struct completion   completion; /* fired if nr_todo reaches 0 */
};

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

/* static data for stop_cpus */
static DEFINE_MUTEX(stop_cpus_mutex);
static bool stop_cpus_in_progress;

static bool stop_machine_initialized = false;

static void cpu_stop_init_done(struct cpu_stop_done *done,
                               unsigned int nr_todo)
{
    memset(done, 0, sizeof(*done));
    atomic_set(&done->nr_todo, nr_todo);
    init_completion(&done->completion);
}

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

/* signal completion unless @done is NULL */
static void cpu_stop_signal_done(struct cpu_stop_done *done)
{
    if (atomic_dec_and_test(&done->nr_todo))
        complete(&done->completion);
}

static void cpu_stopper_thread(unsigned int cpu)
{
    struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
    struct cpu_stop_work *work;

repeat:
    work = NULL;
    raw_spin_lock_irq(&stopper->lock);
    if (!list_empty(&stopper->works)) {
        work = list_first_entry(&stopper->works,
                                struct cpu_stop_work, list);
        list_del_init(&work->list);
    }
    raw_spin_unlock_irq(&stopper->lock);

    if (work) {
        cpu_stop_fn_t fn = work->fn;
        void *arg = work->arg;
        struct cpu_stop_done *done = work->done;
        int ret;

        /* cpu stop callbacks must not sleep, make in_atomic() == T */
        stopper->caller = work->caller;
        stopper->fn = fn;
        preempt_count_inc();
        ret = fn(arg);
        if (done) {
            if (ret)
                done->ret = ret;
            cpu_stop_signal_done(done);
        }
        preempt_count_dec();
        stopper->fn = NULL;
        stopper->caller = 0;
        WARN_ONCE(preempt_count(),
                  "cpu_stop: %ps(%p) leaked preempt count\n", fn, arg);
        goto repeat;
    }
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

static void set_state(struct multi_stop_data *msdata,
                      enum multi_stop_state newstate)
{
    /* Reset ack counter. */
    atomic_set(&msdata->thread_ack, msdata->num_threads);
    smp_wmb();
    WRITE_ONCE(msdata->state, newstate);
}

static void __cpu_stop_queue_work(struct cpu_stopper *stopper,
                                  struct cpu_stop_work *work,
                                  struct wake_q_head *wakeq)
{
    list_add_tail(&work->list, &stopper->works);
    wake_q_add(wakeq, stopper->thread);
}

/* queue @work to @stopper.  if offline, @work is completed immediately */
static bool cpu_stop_queue_work(unsigned int cpu,
                                struct cpu_stop_work *work)
{
    struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
    DEFINE_WAKE_Q(wakeq);
    unsigned long flags;
    bool enabled;

    preempt_disable();
    raw_spin_lock_irqsave(&stopper->lock, flags);
    enabled = stopper->enabled;
    if (enabled)
        __cpu_stop_queue_work(stopper, work, &wakeq);
    else if (work->done)
        cpu_stop_signal_done(work->done);
    raw_spin_unlock_irqrestore(&stopper->lock, flags);

    wake_up_q(&wakeq);
    preempt_enable();

    return enabled;
}

static bool queue_stop_cpus_work(const struct cpumask *cpumask,
                                 cpu_stop_fn_t fn, void *arg,
                                 struct cpu_stop_done *done)
{
    struct cpu_stop_work *work;
    unsigned int cpu;
    bool queued = false;

    /*
     * Disable preemption while queueing to avoid getting
     * preempted by a stopper which might wait for other stoppers
     * to enter @fn which can lead to deadlock.
     */
    preempt_disable();
    stop_cpus_in_progress = true;
    barrier();
    for_each_cpu(cpu, cpumask) {
        work = &per_cpu(cpu_stopper.stop_work, cpu);
        work->fn = fn;
        work->arg = arg;
        work->done = done;
        work->caller = _RET_IP_;
        if (cpu_stop_queue_work(cpu, work))
            queued = true;
    }
    barrier();
    stop_cpus_in_progress = false;
    preempt_enable();

    return queued;
}

static int __stop_cpus(const struct cpumask *cpumask,
                       cpu_stop_fn_t fn, void *arg)
{
    struct cpu_stop_done done;

    cpu_stop_init_done(&done, cpumask_weight(cpumask));
    if (!queue_stop_cpus_work(cpumask, fn, arg, &done))
        return -ENOENT;
    wait_for_completion(&done.completion);
    return done.ret;
}

/**
 * stop_cpus - stop multiple cpus
 * @cpumask: cpus to stop
 * @fn: function to execute
 * @arg: argument to @fn
 *
 * Execute @fn(@arg) on online cpus in @cpumask.  On each target cpu,
 * @fn is run in a process context with the highest priority
 * preempting any task on the cpu and monopolizing it.  This function
 * returns after all executions are complete.
 *
 * This function doesn't guarantee the cpus in @cpumask stay online
 * till @fn completes.  If some cpus go down in the middle, execution
 * on the cpu may happen partially or fully on different cpus.  @fn
 * should either be ready for that or the caller should ensure that
 * the cpus stay online until this function completes.
 *
 * All stop_cpus() calls are serialized making it safe for @fn to wait
 * for all cpus to start executing it.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * -ENOENT if @fn(@arg) was not executed at all because all cpus in
 * @cpumask were offline; otherwise, 0 if all executions of @fn
 * returned 0, any non zero return value if any returned non zero.
 */
static int stop_cpus(const struct cpumask *cpumask, cpu_stop_fn_t fn,
                     void *arg)
{
    int ret;

    /* static works are used, process one request at a time */
    mutex_lock(&stop_cpus_mutex);
    ret = __stop_cpus(cpumask, fn, arg);
    mutex_unlock(&stop_cpus_mutex);
    return ret;
}

notrace void __weak stop_machine_yield(const struct cpumask *cpumask)
{
    cpu_relax();
}

/* Last one to ack a state moves to the next state. */
static void ack_state(struct multi_stop_data *msdata)
{
    if (atomic_dec_and_test(&msdata->thread_ack))
        set_state(msdata, msdata->state + 1);
}

/* This is the cpu_stop function which stops the CPU. */
static int multi_cpu_stop(void *data)
{
    struct multi_stop_data *msdata = data;
    enum multi_stop_state newstate, curstate = MULTI_STOP_NONE;
    int cpu = smp_processor_id(), err = 0;
    const struct cpumask *cpumask;
    unsigned long flags;
    bool is_active;

    /*
     * When called from stop_machine_from_inactive_cpu(), irq might
     * already be disabled.  Save the state and restore it on exit.
     */
    local_save_flags(flags);

    if (!msdata->active_cpus) {
        cpumask = cpu_online_mask;
        is_active = cpu == cpumask_first(cpumask);
    } else {
        cpumask = msdata->active_cpus;
        is_active = cpumask_test_cpu(cpu, cpumask);
    }

    /* Simple state machine */
    do {
        /* Chill out and ensure we re-read multi_stop_state. */
        stop_machine_yield(cpumask);
        newstate = READ_ONCE(msdata->state);
        if (newstate != curstate) {
            curstate = newstate;
            switch (curstate) {
            case MULTI_STOP_DISABLE_IRQ:
                local_irq_disable();
                hard_irq_disable();
                break;
            case MULTI_STOP_RUN:
                if (is_active)
                    err = msdata->fn(msdata->data);
                break;
            default:
                break;
            }
            ack_state(msdata);
        } else if (curstate > MULTI_STOP_PREPARE) {
            /*
             * At this stage all other CPUs we depend on must spin
             * in the same loop. Any reason for hard-lockup should
             * be detected and reported on their side.
             */
            touch_nmi_watchdog();
        }
        rcu_momentary_dyntick_idle();
    } while (curstate != MULTI_STOP_EXIT);

    local_irq_restore(flags);
    return err;
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

    /* Set the initial state and stop all online cpus. */
    set_state(&msdata, MULTI_STOP_PREPARE);
    return stop_cpus(cpu_online_mask, multi_cpu_stop, &msdata);
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

/**
 * stop_one_cpu_nowait - stop a cpu but don't wait for completion
 * @cpu: cpu to stop
 * @fn: function to execute
 * @arg: argument to @fn
 * @work_buf: pointer to cpu_stop_work structure
 *
 * Similar to stop_one_cpu() but doesn't wait for completion.  The
 * caller is responsible for ensuring @work_buf is currently unused
 * and will remain untouched until stopper starts executing @fn.
 *
 * CONTEXT:
 * Don't care.
 *
 * RETURNS:
 * true if cpu_stop_work was queued successfully and @fn will be called,
 * false otherwise.
 */
bool stop_one_cpu_nowait(unsigned int cpu, cpu_stop_fn_t fn, void *arg,
                         struct cpu_stop_work *work_buf)
{
    *work_buf = (struct cpu_stop_work){ .fn = fn, .arg = arg,
        .caller = _RET_IP_, };
    return cpu_stop_queue_work(cpu, work_buf);
}
