// SPDX-License-Identifier: GPL-2.0
/*
 * Real-Time Scheduling Class (mapped to the SCHED_FIFO and SCHED_RR
 * policies)
 */

int sched_rr_timeslice = RR_TIMESLICE;

struct rt_bandwidth def_rt_bandwidth;

typedef struct rt_rq *rt_rq_iter_t;

typedef struct rt_rq *rt_rq_iter_t;

static DEFINE_PER_CPU(cpumask_var_t, local_cpu_mask);

#define for_each_rt_rq(rt_rq, iter, rq) \
    for ((void) iter, rt_rq = &rq->rt; rt_rq; rt_rq = NULL)

#define for_each_sched_rt_entity(rt_se) \
    for (; rt_se; rt_se = NULL)

static inline struct rt_rq *group_rt_rq(struct sched_rt_entity *rt_se)
{
    return NULL;
}

static inline struct rq *rq_of_rt_rq(struct rt_rq *rt_rq)
{
    return container_of(rt_rq, struct rq, rt);
}

static void
enqueue_top_rt_rq(struct rt_rq *rt_rq)
{
    panic("%s: END!\n", __func__);
}

static inline void sched_rt_rq_enqueue(struct rt_rq *rt_rq)
{
    struct rq *rq = rq_of_rt_rq(rt_rq);

    if (!rt_rq->rt_nr_running)
        return;

    enqueue_top_rt_rq(rt_rq);
    resched_curr(rq);
}

static void
dequeue_top_rt_rq(struct rt_rq *rt_rq)
{
    struct rq *rq = rq_of_rt_rq(rt_rq);

    BUG_ON(&rq->rt != rt_rq);

    if (!rt_rq->rt_queued)
        return;
#if 0

    BUG_ON(!rq->nr_running);

    sub_nr_running(rq, rt_rq->rt_nr_running);
    rt_rq->rt_queued = 0;
#endif
    panic("%s: END!\n", __func__);
}

static inline void sched_rt_rq_dequeue(struct rt_rq *rt_rq)
{
    dequeue_top_rt_rq(rt_rq);
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

static inline
struct rt_bandwidth *sched_rt_bandwidth(struct rt_rq *rt_rq)
{
    return &def_rt_bandwidth;
}

static void __enable_runtime(struct rq *rq)
{
    rt_rq_iter_t iter;
    struct rt_rq *rt_rq;

    if (unlikely(!scheduler_running))
        return;

    /*
     * Reset each runqueue's bandwidth settings
     */
    for_each_rt_rq(rt_rq, iter, rq) {
        struct rt_bandwidth *rt_b = sched_rt_bandwidth(rt_rq);

        raw_spin_lock(&rt_b->rt_runtime_lock);
        raw_spin_lock(&rt_rq->rt_runtime_lock);
        rt_rq->rt_runtime = rt_b->rt_runtime;
        rt_rq->rt_time = 0;
        rt_rq->rt_throttled = 0;
        raw_spin_unlock(&rt_rq->rt_runtime_lock);
        raw_spin_unlock(&rt_b->rt_runtime_lock);
    }
}

/* Assumes rq->lock is held */
static void rq_online_rt(struct rq *rq)
{
    if (rq->rt.overloaded)
        rt_set_overload(rq);

    __enable_runtime(rq);

    cpupri_set(&rq->rd->cpupri, rq->cpu, rq->rt.highest_prio.curr);
}

static inline void rt_clear_overload(struct rq *rq)
{
    if (!rq->online)
        return;

    /* the order here really doesn't matter */
    atomic_dec(&rq->rd->rto_count);
    cpumask_clear_cpu(rq->cpu, rq->rd->rto_mask);
}

static inline u64 sched_rt_runtime(struct rt_rq *rt_rq)
{
    return rt_rq->rt_runtime;
}

static inline u64 sched_rt_period(struct rt_rq *rt_rq)
{
    return ktime_to_ns(def_rt_bandwidth.rt_period);
}

/*
 * Ensure this RQ takes back all the runtime it lend to its neighbours.
 */
static void __disable_runtime(struct rq *rq)
{
    struct root_domain *rd = rq->rd;
    rt_rq_iter_t iter;
    struct rt_rq *rt_rq;

    if (unlikely(!scheduler_running))
        return;

    for_each_rt_rq(rt_rq, iter, rq) {
        struct rt_bandwidth *rt_b = sched_rt_bandwidth(rt_rq);
        s64 want;
        int i;

        raw_spin_lock(&rt_b->rt_runtime_lock);
        raw_spin_lock(&rt_rq->rt_runtime_lock);
        /*
         * Either we're all inf and nobody needs to borrow, or we're
         * already disabled and thus have nothing to do, or we have
         * exactly the right amount of runtime to take out.
         */
        if (rt_rq->rt_runtime == RUNTIME_INF ||
            rt_rq->rt_runtime == rt_b->rt_runtime)
            goto balanced;

        panic("%s: 1!\n", __func__);

     balanced:
        /*
         * Disable all the borrow logic by pretending we have inf
         * runtime - in which case borrowing doesn't make sense.
         */
        rt_rq->rt_runtime = RUNTIME_INF;
        rt_rq->rt_throttled = 0;
        raw_spin_unlock(&rt_rq->rt_runtime_lock);
        raw_spin_unlock(&rt_b->rt_runtime_lock);

        /* Make rt_rq available for pick_next_task() */
        sched_rt_rq_enqueue(rt_rq);
    }
}

/* Assumes rq->lock is held */
static void rq_offline_rt(struct rq *rq)
{
    if (rq->rt.overloaded)
        rt_clear_overload(rq);

    __disable_runtime(rq);

    cpupri_set(&rq->rd->cpupri, rq->cpu, CPUPRI_INVALID);
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
static void task_tick_rt(struct rq *rq, struct task_struct *p,
                         int queued)
{
    panic("%s: END!\n", __func__);
}

void __init init_sched_rt_class(void)
{
    unsigned int i;

    for_each_possible_cpu(i) {
        zalloc_cpumask_var_node(&per_cpu(local_cpu_mask, i),
                                GFP_KERNEL, cpu_to_node(i));
    }
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
