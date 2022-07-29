// SPDX-License-Identifier: GPL-2.0
/*
 * Real-Time Scheduling Class (mapped to the SCHED_FIFO and SCHED_RR
 * policies)
 */

struct rt_bandwidth def_rt_bandwidth;

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

void init_rt_rq(struct rt_rq *rt_rq)
{
    struct rt_prio_array *array;
    int i;

    array = &rt_rq->active;
    for (i = 0; i < MAX_RT_PRIO; i++) {
        INIT_LIST_HEAD(array->queue + i);
        __clear_bit(i, array->bitmap);
    }
    /* delimiter for bitsearch: */
    __set_bit(MAX_RT_PRIO, array->bitmap);

    rt_rq->highest_prio.curr = MAX_RT_PRIO-1;
    rt_rq->highest_prio.next = MAX_RT_PRIO-1;
    rt_rq->rt_nr_migratory = 0;
    rt_rq->overloaded = 0;
    plist_head_init(&rt_rq->pushable_tasks);
    /* We start is dequeued state, because no RT tasks are queued */
    rt_rq->rt_queued = 0;

    rt_rq->rt_time = 0;
    rt_rq->rt_throttled = 0;
    rt_rq->rt_runtime = 0;
    raw_spin_lock_init(&rt_rq->rt_runtime_lock);
}

DEFINE_SCHED_CLASS(rt) = {
    .pick_next_task     = pick_next_task_rt,
    .put_prev_task      = put_prev_task_rt,
    .set_next_task      = set_next_task_rt,
};
