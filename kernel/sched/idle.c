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
 * Simple, special scheduling class for the per-CPU idle tasks:
 */
DEFINE_SCHED_CLASS(idle) = {
    .pick_next_task     = pick_next_task_idle,
    .put_prev_task      = put_prev_task_idle,
    .set_next_task      = set_next_task_idle,
    .set_cpus_allowed   = set_cpus_allowed_common,
};
