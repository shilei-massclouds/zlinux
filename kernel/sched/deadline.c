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

static DEFINE_PER_CPU(cpumask_var_t, local_cpu_mask_dl);

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

static void switched_from_dl(struct rq *rq, struct task_struct *p)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * When switching to -deadline, we may overload the rq, then
 * we try to push someone off, if possible.
 */
static void switched_to_dl(struct rq *rq, struct task_struct *p)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * Update the current task's runtime statistics (provided it is still
 * a -deadline task and has not been removed from the dl_rq).
 */
static void update_curr_dl(struct rq *rq)
{
    panic("%s: NO implementation!\n", __func__);
}

static void task_fork_dl(struct task_struct *p)
{
    /*
     * SCHED_DEADLINE tasks cannot fork and this is achieved through
     * sched_fork()
     */
}

/* Locks the rq it finds */
static struct rq *find_lock_later_rq(struct task_struct *task, struct rq *rq)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * Since the task is not running and a reschedule is not going to happen
 * anytime soon on its runqueue, we try pushing it away now.
 */
static void task_woken_dl(struct rq *rq, struct task_struct *p)
{
    panic("%s: NO implementation!\n", __func__);
}

static inline void dl_set_overload(struct rq *rq)
{
    panic("%s: NO implementation!\n", __func__);
}

/* Assumes rq->lock is held */
static void rq_online_dl(struct rq *rq)
{
    if (rq->dl.overloaded)
        dl_set_overload(rq);

    cpudl_set_freecpu(&rq->rd->cpudl, rq->cpu);
    if (rq->dl.dl_nr_running > 0)
        cpudl_set(&rq->rd->cpudl, rq->cpu, rq->dl.earliest_dl.curr);
}

static inline void dl_clear_overload(struct rq *rq)
{
    if (!rq->online)
        return;

    atomic_dec(&rq->rd->dlo_count);
    cpumask_clear_cpu(rq->cpu, rq->rd->dlo_mask);
}

static void cpudl_heapify(struct cpudl *cp, int idx)
{
#if 0
    if (idx > 0 && dl_time_before(cp->elements[parent(idx)].dl,
                                  cp->elements[idx].dl))
        cpudl_heapify_up(cp, idx);
    else
        cpudl_heapify_down(cp, idx);
#endif
    panic("%s: NO implementation!\n", __func__);
}

/*
 * cpudl_clear - remove a CPU from the cpudl max-heap
 * @cp: the cpudl max-heap context
 * @cpu: the target CPU
 *
 * Notes: assumes cpu_rq(cpu)->lock is locked
 *
 * Returns: (void)
 */
void cpudl_clear(struct cpudl *cp, int cpu)
{
    int old_idx, new_cpu;
    unsigned long flags;

    WARN_ON(!cpu_present(cpu));

    raw_spin_lock_irqsave(&cp->lock, flags);

    old_idx = cp->elements[cpu].idx;
    if (old_idx == IDX_INVALID) {
        /*
         * Nothing to remove if old_idx was invalid.
         * This could happen if a rq_offline_dl is
         * called for a CPU without -dl tasks running.
         */
    } else {
        new_cpu = cp->elements[cp->size - 1].cpu;
        cp->elements[old_idx].dl = cp->elements[cp->size - 1].dl;
        cp->elements[old_idx].cpu = new_cpu;
        cp->size--;
        cp->elements[new_cpu].idx = old_idx;
        cp->elements[cpu].idx = IDX_INVALID;
        cpudl_heapify(cp, old_idx);

        cpumask_set_cpu(cpu, cp->free_cpus);
    }
    raw_spin_unlock_irqrestore(&cp->lock, flags);
}

/* Assumes rq->lock is held */
static void rq_offline_dl(struct rq *rq)
{
    if (rq->dl.overloaded)
        dl_clear_overload(rq);

    cpudl_clear(&rq->rd->cpudl, rq->cpu);
    cpudl_clear_freecpu(&rq->rd->cpudl, rq->cpu);
}

static void migrate_task_rq_dl(struct task_struct *p,
                               int new_cpu __maybe_unused)
{
    panic("%s: NO implementation!\n", __func__);
}

static int
select_task_rq_dl(struct task_struct *p, int cpu, int flags)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * Only called when both the current and waking task are -deadline
 * tasks.
 */
static void check_preempt_curr_dl(struct rq *rq, struct task_struct *p,
                                  int flags)
{
    panic("%s: NO implementation!\n", __func__);
}

static int balance_dl(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
{
    panic("%s: NO implementation!\n", __func__);
}

static void enqueue_task_dl(struct rq *rq, struct task_struct *p, int flags)
{
    panic("%s: NO implementation!\n", __func__);
}

static void __dequeue_task_dl(struct rq *rq, struct task_struct *p, int flags)
{
    panic("%s: NO implementation!\n", __func__);
}

static void dequeue_task_dl(struct rq *rq, struct task_struct *p, int flags)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * Yield task semantic for -deadline tasks is:
 *
 *   get off from the CPU until our next instance, with
 *   a new runtime. This is of little use now, since we
 *   don't have a bandwidth reclaiming mechanism. Anyway,
 *   bandwidth reclaiming is planned for the future, and
 *   yield_task_dl will indicate that some spare budget
 *   is available for other task instances to use it.
 */
static void yield_task_dl(struct rq *rq)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * scheduler tick hitting a task of our scheduling class.
 *
 * NOTE: This function can be called remotely by the tick offload that
 * goes along full dynticks. Therefore no local assumption can be made
 * and everything must be accessed through the @rq and @curr passed in
 * parameters.
 */
static void task_tick_dl(struct rq *rq, struct task_struct *p, int queued)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * If the scheduling parameters of a -deadline task changed,
 * a push or pull operation might be needed.
 */
static void prio_changed_dl(struct rq *rq, struct task_struct *p, int oldprio)
{
    panic("%s: NO implementation!\n", __func__);
}

/*
 * This function validates the new parameters of a -deadline task.
 * We ask for the deadline not being zero, and greater or equal
 * than the runtime, as well as the period of being zero or
 * greater than deadline. Furthermore, we have to be sure that
 * user parameters are above the internal resolution of 1us (we
 * check sched_runtime only since it is always the smaller one) and
 * below 2^63 ns (we have to check both sched_deadline and
 * sched_period, as the latter can be zero).
 */
bool __checkparam_dl(const struct sched_attr *attr)
{
    panic("%s: NO implementation!\n", __func__);
}

bool dl_param_changed(struct task_struct *p, const struct sched_attr *attr)
{
    struct sched_dl_entity *dl_se = &p->dl;

    if (dl_se->dl_runtime != attr->sched_runtime ||
        dl_se->dl_deadline != attr->sched_deadline ||
        dl_se->dl_period != attr->sched_period ||
        dl_se->flags != (attr->sched_flags & SCHED_DL_FLAGS))
        return true;

    return false;
}

/*
 * This function clears the sched_dl_entity static params.
 */
void __dl_clear_params(struct task_struct *p)
{
    struct sched_dl_entity *dl_se = &p->dl;

    dl_se->dl_runtime       = 0;
    dl_se->dl_deadline      = 0;
    dl_se->dl_period        = 0;
    dl_se->flags            = 0;
    dl_se->dl_bw            = 0;
    dl_se->dl_density       = 0;

    dl_se->dl_throttled     = 0;
    dl_se->dl_yielded       = 0;
    dl_se->dl_non_contending    = 0;
    dl_se->dl_overrun       = 0;

    dl_se->pi_se            = dl_se;
}

void __init init_sched_dl_class(void)
{
    unsigned int i;

    for_each_possible_cpu(i)
        zalloc_cpumask_var_node(&per_cpu(local_cpu_mask_dl, i),
                                GFP_KERNEL, cpu_to_node(i));
}

/*
 * This is the bandwidth enforcement timer callback. If here, we know
 * a task is not on its dl_rq, since the fact that the timer was running
 * means the task is throttled and needs a runtime replenishment.
 *
 * However, what we actually do depends on the fact the task is active,
 * (it is on its rq) or has been removed from there by a call to
 * dequeue_task_dl(). In the former case we must issue the runtime
 * replenishment and add the task back to the dl_rq; in the latter, we just
 * do nothing but clearing dl_throttled, so that runtime and deadline
 * updating (and the queueing back to dl_rq) will be done by the
 * next call to enqueue_task_dl().
 */
static enum hrtimer_restart dl_task_timer(struct hrtimer *timer)
{
    panic("%s: NO implementation!\n", __func__);
}

void init_dl_task_timer(struct sched_dl_entity *dl_se)
{
    struct hrtimer *timer = &dl_se->dl_timer;

    hrtimer_init(timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_HARD);
    timer->function = dl_task_timer;
}

static enum hrtimer_restart inactive_task_timer(struct hrtimer *timer)
{
    panic("%s: NO implementation!\n", __func__);
}

void init_dl_inactive_task_timer(struct sched_dl_entity *dl_se)
{
    struct hrtimer *timer = &dl_se->inactive_timer;

    hrtimer_init(timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_HARD);
    timer->function = inactive_task_timer;
}

DEFINE_SCHED_CLASS(dl) = {
    .enqueue_task       = enqueue_task_dl,
    .dequeue_task       = dequeue_task_dl,
    .yield_task         = yield_task_dl,

    .check_preempt_curr = check_preempt_curr_dl,

    .pick_next_task     = pick_next_task_dl,
    .put_prev_task      = put_prev_task_dl,
    .set_next_task      = set_next_task_dl,

    .balance            = balance_dl,
    .pick_task          = pick_task_dl,
    .select_task_rq     = select_task_rq_dl,
    .migrate_task_rq    = migrate_task_rq_dl,
    .set_cpus_allowed   = set_cpus_allowed_dl,
    .rq_online          = rq_online_dl,
    .rq_offline         = rq_offline_dl,
    .task_woken         = task_woken_dl,
    .find_lock_rq       = find_lock_later_rq,

    .task_tick          = task_tick_dl,
    .task_fork          = task_fork_dl,

    .prio_changed       = prio_changed_dl,
    .switched_from      = switched_from_dl,
    .switched_to        = switched_to_dl,

    .update_curr        = update_curr_dl,
};
