// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic entry points for the idle threads and
 * implementation of the idle task scheduling class.
 *
 * (NOTE: these are not related to SCHED_IDLE batch scheduled
 *        tasks which are handled in sched/fair.c )
 */

static int __read_mostly cpu_idle_force_poll;

/* Weak implementations for optional arch specific functions */
void __weak arch_cpu_idle_prepare(void) { }
void __weak arch_cpu_idle_enter(void) { }
void __weak arch_cpu_idle_exit(void) { }
void __weak arch_cpu_idle_dead(void) { }
void __weak arch_cpu_idle(void)
{
    cpu_idle_force_poll = 1;
    raw_local_irq_enable();
}

static void
set_next_task_idle(struct rq *rq, struct task_struct *next, bool first)
{
}

struct task_struct *pick_next_task_idle(struct rq *rq)
{
    struct task_struct *next = rq->idle;

    printk("%s: 1\n", __func__);
    set_next_task_idle(rq, next, true);

    return next;
}

static void put_prev_task_idle(struct rq *rq, struct task_struct *prev)
{
}

/*
 * scheduler tick hitting a task of our scheduling class.
 *
 * NOTE: This function can be called remotely by the tick offload that
 * goes along full dynticks. Therefore no local assumption can be made
 * and everything must be accessed through the @rq and @curr passed in
 * parameters.
 */
static void task_tick_idle(struct rq *rq, struct task_struct *curr, int queued)
{
}

static void switched_to_idle(struct rq *rq, struct task_struct *p)
{
    BUG();
}

static void
prio_changed_idle(struct rq *rq, struct task_struct *p, int oldprio)
{
    BUG();
}

static void update_curr_idle(struct rq *rq)
{
}

static struct task_struct *pick_task_idle(struct rq *rq)
{
    return rq->idle;
}

static int
select_task_rq_idle(struct task_struct *p, int cpu, int flags)
{
    return task_cpu(p); /* IDLE tasks as never migrated */
}

static int
balance_idle(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
    return WARN_ON_ONCE(1);
}

/*
 * It is not legal to sleep in the idle task - print a warning
 * message if some code attempts to do it:
 */
static void
dequeue_task_idle(struct rq *rq, struct task_struct *p, int flags)
{
    raw_spin_rq_unlock_irq(rq);
    printk(KERN_ERR "bad: scheduling from the idle thread!\n");
    //dump_stack();
    raw_spin_rq_lock_irq(rq);
}

/*
 * Idle tasks are unconditionally rescheduled:
 */
static void check_preempt_curr_idle(struct rq *rq,
                                    struct task_struct *p,
                                    int flags)
{
    resched_curr(rq);
}

static noinline int __cpuidle cpu_idle_poll(void)
{
    panic("%s: NO implementation!\n", __func__);
}

/**
 * cpuidle_idle_call - the main idle function
 *
 * NOTE: no locks or semaphores should be used here
 *
 * On architectures that support TIF_POLLING_NRFLAG, is called with polling
 * set, and it returns with polling set.  If it ever stops polling, it
 * must clear the polling bit.
 */
static void cpuidle_idle_call(void)
{
    struct cpuidle_device *dev = cpuidle_get_device();
    struct cpuidle_driver *drv = cpuidle_get_cpu_driver(dev);
    int next_state, entered_state;

    /*
     * Check if the idle task must be rescheduled. If it is the
     * case, exit the function after re-enabling the local irq.
     */
    if (need_resched()) {
        local_irq_enable();
        return;
    }

    /*
     * The RCU framework needs to be told that we are entering an idle
     * section, so no more rcu read side critical sections and one more
     * step to the grace period
     */

#if 0
    if (cpuidle_not_available(drv, dev)) {
        tick_nohz_idle_stop_tick();

        default_idle_call();
        goto exit_idle;
    }
#endif

    panic("%s: NO implementation!\n", __func__);

 exit_idle:
    __current_set_polling();

    /*
     * It is up to the idle functions to reenable local interrupts
     */
    if (WARN_ON_ONCE(irqs_disabled()))
        local_irq_enable();
}

/*
 * Generic idle loop implementation
 *
 * Called with polling cleared.
 */
static void do_idle(void)
{
    int cpu = smp_processor_id();

    /*
     * Check if we need to update blocked load
     */
    nohz_run_idle_balance(cpu);

    /*
     * If the arch has a polling bit, we maintain an invariant:
     *
     * Our polling bit is clear if we're not scheduled (i.e. if rq->curr !=
     * rq->idle). This means that, if rq->idle has the polling bit set,
     * then setting need_resched is guaranteed to cause the CPU to
     * reschedule.
     */

    __current_set_polling();
    tick_nohz_idle_enter();

    while (!need_resched()) {
        rmb();

        local_irq_disable();

        if (cpu_is_offline(cpu)) {
#if 0
            tick_nohz_idle_stop_tick();
            cpuhp_report_idle_dead();
            arch_cpu_idle_dead();
#endif
            panic("%s: cpu_is_offline!\n", __func__);
        }

        arch_cpu_idle_enter();
        rcu_nocb_flush_deferred_wakeup();

        /*
         * In poll mode we reenable interrupts and spin. Also if we
         * detected in the wakeup from idle path that the tick
         * broadcast device expired for us, we don't want to go deep
         * idle as we know that the IPI is going to arrive right away.
         */
        if (cpu_idle_force_poll || tick_check_broadcast_expired()) {
            tick_nohz_idle_restart_tick();
            cpu_idle_poll();
        } else {
            cpuidle_idle_call();
        }
        arch_cpu_idle_exit();

        panic("%s: !need_resched!\n", __func__);
    }
    panic("%s: NO implementation!\n", __func__);
}

void cpu_startup_entry(enum cpuhp_state state)
{
    cpuhp_online_idle(state);
    while (1)
        do_idle();
}

/*
 * Simple, special scheduling class for the per-CPU idle tasks:
 */
DEFINE_SCHED_CLASS(idle) = {

    /* no enqueue/yield_task for idle tasks */

    /* dequeue is not valid, we print a debug message there: */
    .dequeue_task       = dequeue_task_idle,

    .check_preempt_curr = check_preempt_curr_idle,

    .pick_next_task     = pick_next_task_idle,
    .put_prev_task      = put_prev_task_idle,
    .set_next_task      = set_next_task_idle,

    .balance            = balance_idle,
    .pick_task          = pick_task_idle,
    .select_task_rq     = select_task_rq_idle,
    .set_cpus_allowed   = set_cpus_allowed_common,

    .task_tick          = task_tick_idle,

    .prio_changed       = prio_changed_idle,
    .switched_to        = switched_to_idle,
    .update_curr        = update_curr_idle,
};
