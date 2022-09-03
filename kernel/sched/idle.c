// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generic entry points for the idle threads and
 * implementation of the idle task scheduling class.
 *
 * (NOTE: these are not related to SCHED_IDLE batch scheduled
 *        tasks which are handled in sched/fair.c )
 */

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
static void check_preempt_curr_idle(struct rq *rq, struct task_struct *p,
                                    int flags)
{
    resched_curr(rq);
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
