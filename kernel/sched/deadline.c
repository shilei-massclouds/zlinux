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

static inline struct task_struct *dl_task_of(struct sched_dl_entity *dl_se)
{
    return container_of(dl_se, struct task_struct, dl);
}

static void put_prev_task_dl(struct rq *rq, struct task_struct *p)
{
    panic("%s: NO implementation!\n", __func__);
}

static void set_next_task_dl(struct rq *rq, struct task_struct *p, bool first)
{
    panic("%s: NO implementation!\n", __func__);
}

#define __node_2_dle(node) \
    rb_entry((node), struct sched_dl_entity, rb_node)

static struct sched_dl_entity *pick_next_dl_entity(struct dl_rq *dl_rq)
{
    struct rb_node *left = rb_first_cached(&dl_rq->root);

    if (!left)
        return NULL;

    return __node_2_dle(left);
}

static struct task_struct *pick_task_dl(struct rq *rq)
{
    struct sched_dl_entity *dl_se;
    struct dl_rq *dl_rq = &rq->dl;
    struct task_struct *p;

    if (!sched_dl_runnable(rq))
        return NULL;

    dl_se = pick_next_dl_entity(dl_rq);
    BUG_ON(!dl_se);
    p = dl_task_of(dl_se);

    return p;
}

static struct task_struct *pick_next_task_dl(struct rq *rq)
{
    struct task_struct *p;

    p = pick_task_dl(rq);
    if (p)
        set_next_task_dl(rq, p, true);

    return p;
}

static void set_cpus_allowed_dl(struct task_struct *p,
                                const struct cpumask *new_mask,
                                u32 flags)
{
    struct root_domain *src_rd;
    struct rq *rq;

    BUG_ON(!dl_task(p));

    rq = task_rq(p);
    src_rd = rq->rd;

    panic("%s: NO implementation!\n", __func__);
}

void init_dl_rq(struct dl_rq *dl_rq)
{
    dl_rq->root = RB_ROOT_CACHED;

    /* zero means no -deadline tasks */
    dl_rq->earliest_dl.curr = dl_rq->earliest_dl.next = 0;

    dl_rq->dl_nr_migratory = 0;
    dl_rq->overloaded = 0;
    dl_rq->pushable_dl_tasks_root = RB_ROOT_CACHED;

    dl_rq->running_bw = 0;
    dl_rq->this_bw = 0;
    //init_dl_rq_bw_ratio(dl_rq);
}

DEFINE_SCHED_CLASS(dl) = {
    .pick_next_task     = pick_next_task_dl,
    .put_prev_task      = put_prev_task_dl,
    .set_next_task      = set_next_task_dl,

    .set_cpus_allowed   = set_cpus_allowed_dl,
    .pick_task          = pick_task_dl,
};
