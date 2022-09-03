// SPDX-License-Identifier: GPL-2.0
/*
 * Real-Time Scheduling Class (mapped to the SCHED_FIFO and SCHED_RR
 * policies)
 */

int sched_rr_timeslice = RR_TIMESLICE;

struct rt_bandwidth def_rt_bandwidth;

typedef struct rt_rq *rt_rq_iter_t;

static inline struct rt_rq *group_rt_rq(struct sched_rt_entity *rt_se)
{
    return NULL;
}

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

/*
 * Priority of the task has changed. This may cause
 * us to initiate a push or pull.
 */
static void
prio_changed_rt(struct rq *rq, struct task_struct *p, int oldprio)
{
    panic("%s: END!\n", __func__);
}

/*
 * When switching a task to RT, we may overload the runqueue
 * with RT tasks. In this case we try to push them off to
 * other runqueues.
 */
static void switched_to_rt(struct rq *rq, struct task_struct *p)
{
    panic("%s: END!\n", __func__);
}

/*
 * Update the current task's runtime statistics. Skip current tasks that
 * are not in our scheduling class.
 */
static void update_curr_rt(struct rq *rq)
{
    panic("%s: END!\n", __func__);
}

static unsigned int get_rr_interval_rt(struct rq *rq, struct task_struct *task)
{
    /*
     * Time slice is 0 for SCHED_FIFO tasks
     */
    if (task->policy == SCHED_RR)
        return sched_rr_timeslice;
    else
        return 0;
}

/*
 * Adding/removing a task to/from a priority array:
 */
static void
enqueue_task_rt(struct rq *rq, struct task_struct *p, int flags)
{
    panic("%s: END!\n", __func__);
}

static void dequeue_task_rt(struct rq *rq, struct task_struct *p, int flags)
{
    panic("%s: END!\n", __func__);
}

static void yield_task_rt(struct rq *rq)
{
    panic("%s: END!\n", __func__);
}

static int
select_task_rq_rt(struct task_struct *p, int cpu, int flags)
{
    panic("%s: END!\n", __func__);
}

/*
 * Preempt the current task with a newly woken task if needed:
 */
static void check_preempt_curr_rt(struct rq *rq, struct task_struct *p,
                                  int flags)
{
    panic("%s: END!\n", __func__);
}

static int balance_rt(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
{
    panic("%s: END!\n", __func__);
}

/* Will lock the rq it finds */
static struct rq *find_lock_lowest_rq(struct task_struct *task, struct rq *rq)
{
    panic("%s: END!\n", __func__);
}

/*
 * If we are not running and we are not going to reschedule soon, we should
 * try to push tasks away now
 */
static void task_woken_rt(struct rq *rq, struct task_struct *p)
{
    panic("%s: END!\n", __func__);
}

static inline void rt_set_overload(struct rq *rq)
{
    panic("%s: END!\n", __func__);
}

static void __enable_runtime(struct rq *rq)
{
    rt_rq_iter_t iter;
    struct rt_rq *rt_rq;

    if (unlikely(!scheduler_running))
        return;

    panic("%s: END!\n", __func__);
}

/* Assumes rq->lock is held */
static void rq_online_rt(struct rq *rq)
{
    if (rq->rt.overloaded)
        rt_set_overload(rq);

    __enable_runtime(rq);

    cpupri_set(&rq->rd->cpupri, rq->cpu, rq->rt.highest_prio.curr);
}

/* Assumes rq->lock is held */
static void rq_offline_rt(struct rq *rq)
{
    panic("%s: END!\n", __func__);
}

/*
 * When switch from the rt queue, we bring ourselves to a position
 * that we might want to pull RT tasks from other runqueues.
 */
static void switched_from_rt(struct rq *rq, struct task_struct *p)
{
    panic("%s: END!\n", __func__);
}

/*
 * scheduler tick hitting a task of our scheduling class.
 *
 * NOTE: This function can be called remotely by the tick offload that
 * goes along full dynticks. Therefore no local assumption can be made
 * and everything must be accessed through the @rq and @curr passed in
 * parameters.
 */
static void task_tick_rt(struct rq *rq, struct task_struct *p, int queued)
{
    panic("%s: END!\n", __func__);
}

DEFINE_SCHED_CLASS(rt) = {
    .enqueue_task       = enqueue_task_rt,
    .dequeue_task       = dequeue_task_rt,
    .yield_task         = yield_task_rt,

    .check_preempt_curr = check_preempt_curr_rt,

    .pick_next_task     = pick_next_task_rt,
    .put_prev_task      = put_prev_task_rt,
    .set_next_task      = set_next_task_rt,

    .balance            = balance_rt,
    .pick_task          = pick_task_rt,
    .select_task_rq     = select_task_rq_rt,
    .set_cpus_allowed   = set_cpus_allowed_common,
    .rq_online          = rq_online_rt,
    .rq_offline         = rq_offline_rt,
    .task_woken         = task_woken_rt,
    .switched_from      = switched_from_rt,
    .find_lock_rq       = find_lock_lowest_rq,

    .task_tick          = task_tick_rt,

    .get_rr_interval    = get_rr_interval_rt,

    .prio_changed       = prio_changed_rt,
    .switched_to        = switched_to_rt,

    .update_curr        = update_curr_rt,
};
