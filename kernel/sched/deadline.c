// SPDX-License-Identifier: GPL-2.0
/*
 * Deadline Scheduling Class (SCHED_DEADLINE)
 *
 * Earliest Deadline First (EDF) + Constant Bandwidth Server (CBS).
 *
 * Tasks that periodically executes their instances for less than their
 * runtime won't miss any of their deadlines.
 * Tasks that are not periodic or sporadic or that tries to execute more
 * than their reserved bandwidth will be slowed down (and may potentially
 * miss some of their deadlines), and won't affect any other task.
 *
 * Copyright (C) 2012 Dario Faggioli <raistlin@linux.it>,
 *                    Juri Lelli <juri.lelli@gmail.com>,
 *                    Michael Trimarchi <michael@amarulasolutions.com>,
 *                    Fabio Checconi <fchecconi@gmail.com>
 */

static void put_prev_task_dl(struct rq *rq, struct task_struct *p)
{
    panic("%s: NO implementation!\n", __func__);
}

static void set_next_task_dl(struct rq *rq, struct task_struct *p, bool first)
{
    panic("%s: NO implementation!\n", __func__);
}

static struct task_struct *pick_next_task_dl(struct rq *rq)
{
    panic("%s: NO implementation!\n", __func__);
#if 0
    struct task_struct *p;

    p = pick_task_dl(rq);
    if (p)
        set_next_task_dl(rq, p, true);

    return p;
#endif
}

DEFINE_SCHED_CLASS(dl) = {
    .pick_next_task     = pick_next_task_dl,
    .put_prev_task      = put_prev_task_dl,
    .set_next_task      = set_next_task_dl,
};
