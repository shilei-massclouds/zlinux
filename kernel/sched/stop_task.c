// SPDX-License-Identifier: GPL-2.0
/*
 * stop-task scheduling class.
 *
 * The stop task is the highest priority task in the system, it preempts
 * everything and will be preempted by nothing.
 *
 * See kernel/stop_machine.c
 */

static struct task_struct *pick_task_stop(struct rq *rq)
{
    if (!sched_stop_runnable(rq))
        return NULL;

    return rq->stop;
}

static void
set_next_task_stop(struct rq *rq, struct task_struct *stop, bool first)
{
    panic("%s: NO implementation!\n", __func__);
#if 0
    stop->se.exec_start = rq_clock_task(rq);
#endif
}

static struct task_struct *pick_next_task_stop(struct rq *rq)
{
    struct task_struct *p = pick_task_stop(rq);

    if (p)
        set_next_task_stop(rq, p, true);

    return p;
}

static void put_prev_task_stop(struct rq *rq, struct task_struct *prev)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * Simple, special scheduling class for the per-CPU stop tasks:
 */
DEFINE_SCHED_CLASS(stop) = {
    .pick_next_task     = pick_next_task_stop,
    .put_prev_task      = put_prev_task_stop,
    .set_next_task      = set_next_task_stop,
    .set_cpus_allowed   = set_cpus_allowed_common,
};
