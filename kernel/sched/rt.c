// SPDX-License-Identifier: GPL-2.0
/*
 * Real-Time Scheduling Class (mapped to the SCHED_FIFO and SCHED_RR
 * policies)
 */

static struct task_struct *_pick_next_task_rt(struct rq *rq)
{
    panic("%s: END!\n", __func__);
#if 0
    struct sched_rt_entity *rt_se;
    struct rt_rq *rt_rq  = &rq->rt;

    do {
        rt_se = pick_next_rt_entity(rt_rq);
        BUG_ON(!rt_se);
        rt_rq = group_rt_rq(rt_se);
    } while (rt_rq);

    return rt_task_of(rt_se);
#endif
}

static struct task_struct *pick_task_rt(struct rq *rq)
{
    struct task_struct *p;

    if (!sched_rt_runnable(rq))
        return NULL;

    p = _pick_next_task_rt(rq);

    return p;
}

static inline void
set_next_task_rt(struct rq *rq, struct task_struct *p, bool first)
{
    panic("%s: END!\n", __func__);
}

static void put_prev_task_rt(struct rq *rq, struct task_struct *p)
{
    panic("%s: END!\n", __func__);
}

static struct task_struct *pick_next_task_rt(struct rq *rq)
{
    struct task_struct *p = pick_task_rt(rq);

    if (p)
        set_next_task_rt(rq, p, true);

    return p;
}

DEFINE_SCHED_CLASS(rt) = {
    .pick_next_task     = pick_next_task_rt,
    .put_prev_task      = put_prev_task_rt,
    .set_next_task      = set_next_task_rt,
};
