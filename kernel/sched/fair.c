// SPDX-License-Identifier: GPL-2.0
/*
 * Completely Fair Scheduling (CFS) Class (SCHED_NORMAL/SCHED_BATCH)
 *
 *  Copyright (C) 2007 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 *  Interactivity improvements by Mike Galbraith
 *  (C) 2007 Mike Galbraith <efault@gmx.de>
 *
 *  Various enhancements by Dmitry Adamushko.
 *  (C) 2007 Dmitry Adamushko <dmitry.adamushko@gmail.com>
 *
 *  Group scheduling enhancements by Srivatsa Vaddagiri
 *  Copyright IBM Corporation, 2007
 *  Author: Srivatsa Vaddagiri <vatsa@linux.vnet.ibm.com>
 *
 *  Scaled math optimizations by Thomas Gleixner
 *  Copyright (C) 2007, Thomas Gleixner <tglx@linutronix.de>
 *
 *  Adaptive scheduling granularity, math enhancements by Peter Zijlstra
 *  Copyright (C) 2007 Red Hat, Inc., Peter Zijlstra
 */
#include <linux/mmap_lock.h>
#if 0
#include <linux/energy_model.h>
#include <linux/hugetlb_inline.h>
#include <linux/jiffies.h>
#include <linux/mm_api.h>
#endif
#include <linux/highmem.h>
#include <linux/spinlock_api.h>
#include <linux/topology.h>
#if 0
#include <linux/cpumask_api.h>
#include <linux/lockdep_api.h>
#include <linux/softirq.h>
#include <linux/refcount_api.h>
#include <linux/sched/cond_resched.h>
#include <linux/sched/cputime.h>
#endif
#include <linux/sched/isolation.h>
#include <linux/sched/clock.h>

#include <linux/cpuidle.h>
#if 0
#include <linux/interrupt.h>
#include <linux/mempolicy.h>
#include <linux/mutex_api.h>
#include <linux/profile.h>
#include <linux/psi.h>
#include <linux/task_work.h>

#include <asm/switch_to.h>

#include <linux/sched/cond_resched.h>
#endif
#include <linux/ratelimit.h>

#include "sched.h"
#include "stats.h"
#include "pelt.h"
//#include "autogroup.h"

/* Walk up scheduling entities hierarchy */
#define for_each_sched_entity(se) \
    for (; se; se = se->parent)

#define __node_2_se(node) \
    rb_entry((node), struct sched_entity, run_node)

/*
 * Unsigned subtract and clamp on underflow.
 *
 * Explicitly do a load-store to ensure the intermediate value never hits
 * memory. This allows lockless observations without ever seeing the negative
 * values.
 */
#define sub_positive(_ptr, _val) do {               \
    typeof(_ptr) ptr = (_ptr);              \
    typeof(*ptr) val = (_val);              \
    typeof(*ptr) res, var = READ_ONCE(*ptr);        \
    res = var - val;                    \
    if (res > var)                      \
        res = 0;                    \
    WRITE_ONCE(*ptr, res);                  \
} while (0)

#define WMULT_CONST (~0U)
#define WMULT_SHIFT 32

static struct {
    cpumask_var_t idle_cpus_mask;
    atomic_t nr_cpus;
    int has_blocked;        /* Idle CPUS has blocked load */
    int needs_update;       /* Newly idle CPUs need their next_balance collated */
    unsigned long next_balance;     /* in jiffy units */
    unsigned long next_blocked; /* Next update of blocked load in jiffies */
} nohz ____cacheline_aligned;

const_debug unsigned int sysctl_sched_migration_cost = 500000UL;

static unsigned long __read_mostly max_load_balance_interval = HZ/10;

int sched_thermal_decay_shift;

/*
 * SCHED_OTHER wake-up granularity.
 *
 * This option delays the preemption effects of decoupled workloads
 * and reduces their over-scheduling. Synchronous workloads will still
 * have immediate wakeup/sleep latencies.
 *
 * (default: 1 msec * (1 + ilog(ncpus)), units: nanoseconds)
 */
unsigned int sysctl_sched_wakeup_granularity = 1000000UL;
static unsigned int normalized_sysctl_sched_wakeup_granularity  = 1000000UL;

/* a cfs_rq won't donate quota below this amount */
static const u64 min_cfs_rq_runtime = 1 * NSEC_PER_MSEC;
/* minimum remaining period time to redistribute slack quota */
static const u64 min_bandwidth_expiration = 2 * NSEC_PER_MSEC;
/* how long we wait to gather additional slack before distributing */
static const u64 cfs_bandwidth_slack_period = 5 * NSEC_PER_MSEC;

/*
 * The initial- and re-scaling of tunables is configurable
 *
 * Options are:
 *
 *   SCHED_TUNABLESCALING_NONE - unscaled, always *1
 *   SCHED_TUNABLESCALING_LOG - scaled logarithmical, *1+ilog(ncpus)
 *   SCHED_TUNABLESCALING_LINEAR - scaled linear, *ncpus
 *
 * (default SCHED_TUNABLESCALING_LOG = *(1+ilog(ncpus))
 */
unsigned int sysctl_sched_tunable_scaling = SCHED_TUNABLESCALING_LOG;

/*
 * This value is kept at sysctl_sched_latency/sysctl_sched_min_granularity
 */
static unsigned int sched_nr_latency = 8;

static inline
void update_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se,
                     int flags);

static struct static_key __cfs_bandwidth_used;

static void update_cfs_group(struct sched_entity *se);

static int newidle_balance(struct rq *this_rq, struct rq_flags *rf);

static inline bool cfs_bandwidth_used(void)
{
    return static_key_false(&__cfs_bandwidth_used);
}

/* check whether cfs_rq, or any parent, is throttled */
static inline int throttled_hierarchy(struct cfs_rq *cfs_rq)
{
    return cfs_bandwidth_used() && cfs_rq->throttle_count;
}

static inline struct sched_entity *parent_entity(struct sched_entity *se)
{
    return se->parent;
}

static inline bool entity_before(struct sched_entity *a, struct sched_entity *b)
{
    return (s64)(a->vruntime - b->vruntime) < 0;
}

static inline bool __entity_less(struct rb_node *a, const struct rb_node *b)
{
    return entity_before(__node_2_se(a), __node_2_se(b));
}

/*
 * Enqueue an entity into the rb-tree:
 */
static void __enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    rb_add_cached(&se->run_node, &cfs_rq->tasks_timeline, __entity_less);
}

static void __dequeue_entity(struct cfs_rq *cfs_rq,
                             struct sched_entity *se)
{
    rb_erase_cached(&se->run_node, &cfs_rq->tasks_timeline);
}

static int tg_is_idle(struct task_group *tg)
{
    return tg->idle > 0;
}

static int cfs_rq_is_idle(struct cfs_rq *cfs_rq)
{
    return cfs_rq->idle > 0;
}

static int se_is_idle(struct sched_entity *se)
{
    if (entity_is_task(se))
        return task_has_idle_policy(task_of(se));
    return cfs_rq_is_idle(group_cfs_rq(se));
}

static inline
void update_load_add(struct load_weight *lw, unsigned long inc)
{
    lw->weight += inc;
    lw->inv_weight = 0;
}

static inline
void update_load_sub(struct load_weight *lw, unsigned long dec)
{
    lw->weight -= dec;
    lw->inv_weight = 0;
}

static inline
void update_load_set(struct load_weight *lw, unsigned long w)
{
    lw->weight = w;
    lw->inv_weight = 0;
}

static void
account_entity_enqueue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    update_load_add(&cfs_rq->load, se->load.weight);

    if (entity_is_task(se)) {
        struct rq *rq = rq_of(cfs_rq);

        list_add(&se->group_node, &rq->cfs_tasks);
    }

    cfs_rq->nr_running++;
    if (se_is_idle(se))
        cfs_rq->idle_nr_running++;
}

static void
account_entity_dequeue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    update_load_sub(&cfs_rq->load, se->load.weight);
    if (entity_is_task(se)) {
        list_del_init(&se->group_node);
    }
    cfs_rq->nr_running--;
    if (se_is_idle(se))
        cfs_rq->idle_nr_running--;
}

static inline bool list_add_leaf_cfs_rq(struct cfs_rq *cfs_rq)
{
    struct rq *rq = rq_of(cfs_rq);
    int cpu = cpu_of(rq);

    if (cfs_rq->on_list)
        return rq->tmp_alone_branch == &rq->leaf_cfs_rq_list;

    cfs_rq->on_list = 1;

    /*
     * Ensure we either appear before our parent (if already
     * enqueued) or force our parent to appear after us when it is
     * enqueued. The fact that we always enqueue bottom-up
     * reduces this to two cases and a special case for the root
     * cfs_rq. Furthermore, it also means that we will always reset
     * tmp_alone_branch either when the branch is connected
     * to a tree or when we reach the top of the tree
     */
    if (cfs_rq->tg->parent &&
        cfs_rq->tg->parent->cfs_rq[cpu]->on_list) {

        panic("%s: 1!", __func__);
    }

    if (!cfs_rq->tg->parent) {
        /*
         * cfs rq without parent should be put
         * at the tail of the list.
         */
        list_add_tail_rcu(&cfs_rq->leaf_cfs_rq_list,
                          &rq->leaf_cfs_rq_list);
        /*
         * We have reach the top of a tree so we can reset
         * tmp_alone_branch to the beginning of the list.
         */
        rq->tmp_alone_branch = &rq->leaf_cfs_rq_list;
        return true;
    }

    panic("%s: NO implementation!", __func__);
}

/*
 * When a group wakes up we want to make sure that its quota is not already
 * expired/exceeded, otherwise it may be allowed to steal additional ticks of
 * runtime as update_curr() throttling can not trigger until it's on-rq.
 */
static void check_enqueue_throttle(struct cfs_rq *cfs_rq)
{
    if (!cfs_bandwidth_used())
        return;

    panic("%s: NO implementation!", __func__);
}

static void
enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
    bool renorm = !(flags & ENQUEUE_WAKEUP) || (flags & ENQUEUE_MIGRATED);
    bool curr = cfs_rq->curr == se;

    /*
     * If we're the current task, we must renormalise before calling
     * update_curr().
     */
    if (renorm && curr)
        se->vruntime += cfs_rq->min_vruntime;

    account_entity_enqueue(cfs_rq, se);

    if (!curr)
        __enqueue_entity(cfs_rq, se);
    se->on_rq = 1;

    /*
     * When bandwidth control is enabled, cfs might have been removed
     * because of a parent been throttled but cfs->nr_running > 1. Try to
     * add it unconditionally.
     */
    if (cfs_rq->nr_running == 1 || cfs_bandwidth_used())
        list_add_leaf_cfs_rq(cfs_rq);

    if (cfs_rq->nr_running == 1)
        check_enqueue_throttle(cfs_rq);
}

static unsigned long capacity_of(int cpu)
{
    return cpu_rq(cpu)->cpu_capacity;
}

/*
 * The margin used when comparing utilization with CPU capacity.
 *
 * (default: ~20%)
 */
#define fits_capacity(cap, max) ((cap) * 1280 < (max) * 1024)

static inline bool cpu_overutilized(int cpu)
{
    return !fits_capacity(cpu_util_cfs(cpu), capacity_of(cpu));
}

static inline void update_overutilized_status(struct rq *rq)
{
    if (!READ_ONCE(rq->rd->overutilized) && cpu_overutilized(rq->cpu)) {
        WRITE_ONCE(rq->rd->overutilized, SG_OVERUTILIZED);
    }
}

static inline void assert_list_leaf_cfs_rq(struct rq *rq)
{
    SCHED_WARN_ON(rq->tmp_alone_branch != &rq->leaf_cfs_rq_list);
}

/*
 * Optional action to be done while updating the load average
 */
#define UPDATE_TG       0x1
#define SKIP_AGE_LOAD   0x2
#define DO_ATTACH       0x4

static inline unsigned long _task_util_est(struct task_struct *p)
{
    struct util_est ue = READ_ONCE(p->se.avg.util_est);

    return max(ue.ewma, (ue.enqueued & ~UTIL_AVG_UNCHANGED));
}

static inline void util_est_enqueue(struct cfs_rq *cfs_rq,
                                    struct task_struct *p)
{
    unsigned int enqueued;

    if (!sched_feat(UTIL_EST))
        return;

    /* Update root cfs_rq's estimated utilization */
    enqueued  = cfs_rq->avg.util_est.enqueued;
    enqueued += _task_util_est(p);
    WRITE_ONCE(cfs_rq->avg.util_est.enqueued, enqueued);
}

static inline
void cpufreq_update_util(struct rq *rq, unsigned int flags){
}

static inline int cfs_rq_throttled(struct cfs_rq *cfs_rq)
{
    return cfs_bandwidth_used() && cfs_rq->throttled;
}

/*
 * called from enqueue/dequeue and updates the hrtick when the
 * current task is from our class and nr_running is low enough
 * to matter.
 */
static void hrtick_update(struct rq *rq)
{
    struct task_struct *curr = rq->curr;

    if (!hrtick_enabled_fair(rq) ||
        curr->sched_class != &fair_sched_class)
        return;

#if 0
    if (cfs_rq_of(&curr->se)->nr_running < sched_nr_latency)
        hrtick_start_fair(rq, curr);
#endif
    panic("%s: NO implementation!", __func__);
}

/*
 * The enqueue_task method is called before nr_running is
 * increased. Here we update the fair scheduling stats and
 * then put the task into the rbtree:
 */
static void
enqueue_task_fair(struct rq *rq, struct task_struct *p, int flags)
{
    struct cfs_rq *cfs_rq;
    struct sched_entity *se = &p->se;
    int idle_h_nr_running = task_has_idle_policy(p);
    int task_new = !(flags & ENQUEUE_WAKEUP);

    /*
     * The code below (indirectly) updates schedutil which looks at
     * the cfs_rq utilization to select a frequency.
     * Let's add the task's estimated utilization to the cfs_rq's
     * estimated utilization, before we update schedutil.
     */
    util_est_enqueue(&rq->cfs, p);

    /*
     * If in_iowait is set, the code below may not trigger any cpufreq
     * utilization updates, so do it here explicitly with the IOWAIT flag
     * passed.
     */
    if (p->in_iowait)
        cpufreq_update_util(rq, SCHED_CPUFREQ_IOWAIT);

    for_each_sched_entity(se) {
        if (se->on_rq)
            break;

        cfs_rq = cfs_rq_of(se);
        enqueue_entity(cfs_rq, se, flags);

        cfs_rq->h_nr_running++;
        cfs_rq->idle_h_nr_running += idle_h_nr_running;

        if (cfs_rq_is_idle(cfs_rq))
            idle_h_nr_running = 1;

        /* end evaluation on encountering a throttled cfs_rq */
        if (cfs_rq_throttled(cfs_rq))
            goto enqueue_throttle;

        flags = ENQUEUE_WAKEUP;
    }

    printk("%s: 0 \n", __func__);
    for_each_sched_entity(se) {
        cfs_rq = cfs_rq_of(se);

        printk("%s: 1 \n", __func__);
        update_load_avg(cfs_rq, se, UPDATE_TG);
        se_update_runnable(se);
        update_cfs_group(se);

        printk("%s: 2 \n", __func__);
        cfs_rq->h_nr_running++;
        cfs_rq->idle_h_nr_running += idle_h_nr_running;

        if (cfs_rq_is_idle(cfs_rq))
            idle_h_nr_running = 1;

        /* end evaluation on encountering a throttled cfs_rq */
        if (cfs_rq_throttled(cfs_rq))
            goto enqueue_throttle;

#if 0
       /*
        * One parent has been throttled and cfs_rq removed from the
        * list. Add it back to not break the leaf list.
        */
       if (throttled_hierarchy(cfs_rq))
           list_add_leaf_cfs_rq(cfs_rq);
#endif

        panic("%s: 1!", __func__);
    }

    /* At this point se is NULL and we are at root level*/
    add_nr_running(rq, 1);

    /*
     * Since new tasks are assigned an initial util_avg equal to
     * half of the spare capacity of their CPU, tiny tasks have the
     * ability to cross the overutilized threshold, which will
     * result in the load balancer ruining all the task placement
     * done by EAS. As a way to mitigate that effect, do not account
     * for the first enqueue operation of new tasks during the
     * overutilized flag detection.
     *
     * A better way of solving this problem would be to wait for
     * the PELT signals of tasks to converge before taking them
     * into account, but that is not straightforward to implement,
     * and the following generally works well enough in practice.
     */
    if (!task_new)
        update_overutilized_status(rq);

 enqueue_throttle:
    if (cfs_bandwidth_used()) {
        /*
         * When bandwidth control is enabled; the cfs_rq_throttled()
         * breaks in the above iteration can result in incomplete
         * leaf list maintenance, resulting in triggering the assertion
         * below.
         */
        for_each_sched_entity(se) {
            cfs_rq = cfs_rq_of(se);

            if (list_add_leaf_cfs_rq(cfs_rq))
                break;
        }
    }

    assert_list_leaf_cfs_rq(rq);

    hrtick_update(rq);
}

/* Runqueue only has SCHED_IDLE tasks enqueued */
static int sched_idle_rq(struct rq *rq)
{
    return unlikely(rq->nr_running ==
                    rq->cfs.idle_h_nr_running && rq->nr_running);
}

static inline
void util_est_dequeue(struct cfs_rq *cfs_rq, struct task_struct *p)
{
    unsigned int enqueued;

    if (!sched_feat(UTIL_EST))
        return;

    /* Update root cfs_rq's estimated utilization */
    enqueued  = cfs_rq->avg.util_est.enqueued;
    enqueued -= min_t(unsigned int, enqueued, _task_util_est(p));
    WRITE_ONCE(cfs_rq->avg.util_est.enqueued, enqueued);
}

static void __update_inv_weight(struct load_weight *lw)
{
    unsigned long w;

    if (likely(lw->inv_weight))
        return;

    w = scale_load_down(lw->weight);

    if (BITS_PER_LONG > 32 && unlikely(w >= WMULT_CONST))
        lw->inv_weight = 1;
    else if (unlikely(!w))
        lw->inv_weight = WMULT_CONST;
    else
        lw->inv_weight = WMULT_CONST / w;
}

/*
 * delta_exec * weight / lw.weight
 *   OR
 * (delta_exec * (weight * lw->inv_weight)) >> WMULT_SHIFT
 *
 * Either weight := NICE_0_LOAD and lw \e sched_prio_to_wmult[], in which case
 * we're guaranteed shift stays positive because inv_weight is guaranteed to
 * fit 32 bits, and NICE_0_LOAD gives another 10 bits; therefore shift >= 22.
 *
 * Or, weight =< lw.weight (because lw.weight is the runqueue weight), thus
 * weight/lw.weight <= 1, and therefore our shift will also be positive.
 */
static u64 __calc_delta(u64 delta_exec, unsigned long weight,
                        struct load_weight *lw)
{
    u64 fact = scale_load_down(weight);
    u32 fact_hi = (u32)(fact >> 32);
    int shift = WMULT_SHIFT;
    int fs;

    __update_inv_weight(lw);

    if (unlikely(fact_hi)) {
        fs = fls(fact_hi);
        shift -= fs;
        fact >>= fs;
    }

    fact = mul_u32_u32(fact, lw->inv_weight);

    fact_hi = (u32)(fact >> 32);
    if (fact_hi) {
        fs = fls(fact_hi);
        shift -= fs;
        fact >>= fs;
    }

    return mul_u64_u32_shr(delta_exec, fact, shift);
}

/*
 * delta /= w
 */
static inline u64 calc_delta_fair(u64 delta, struct sched_entity *se)
{
    if (unlikely(se->load.weight != NICE_0_LOAD))
        delta = __calc_delta(delta, NICE_0_LOAD, &se->load);

    return delta;
}

/**************************************************************
 * Scheduling class tree data structure manipulation methods:
 */

static inline u64 max_vruntime(u64 max_vruntime, u64 vruntime)
{
    s64 delta = (s64)(vruntime - max_vruntime);
    if (delta > 0)
        max_vruntime = vruntime;

    return max_vruntime;
}

static inline u64 min_vruntime(u64 min_vruntime, u64 vruntime)
{
    s64 delta = (s64)(vruntime - min_vruntime);
    if (delta < 0)
        min_vruntime = vruntime;

    return min_vruntime;
}

static void update_min_vruntime(struct cfs_rq *cfs_rq)
{
    struct sched_entity *curr = cfs_rq->curr;
    struct rb_node *leftmost = rb_first_cached(&cfs_rq->tasks_timeline);

    u64 vruntime = cfs_rq->min_vruntime;

    if (curr) {
        if (curr->on_rq)
            vruntime = curr->vruntime;
        else
            curr = NULL;
    }

    if (leftmost) { /* non-empty tree */
        struct sched_entity *se = __node_2_se(leftmost);

        if (!curr)
            vruntime = se->vruntime;
        else
            vruntime = min_vruntime(vruntime, se->vruntime);
    }

    /* ensure we never gain time by being placed backwards. */
    cfs_rq->min_vruntime = max_vruntime(cfs_rq->min_vruntime, vruntime);
}

/*
 * Update the current task's runtime statistics.
 */
static void update_curr(struct cfs_rq *cfs_rq)
{
    struct sched_entity *curr = cfs_rq->curr;
    u64 now = rq_clock_task(rq_of(cfs_rq));
    u64 delta_exec;

    if (unlikely(!curr))
        return;

    delta_exec = now - curr->exec_start;
    if (unlikely((s64)delta_exec <= 0))
        return;

    curr->exec_start = now;

    curr->sum_exec_runtime += delta_exec;
    schedstat_add(cfs_rq->exec_clock, delta_exec);

    curr->vruntime += calc_delta_fair(delta_exec, curr);
    update_min_vruntime(cfs_rq);

    if (entity_is_task(curr)) {
        struct task_struct *curtask = task_of(curr);

        //cgroup_account_cputime(curtask, delta_exec);
        //account_group_exec_runtime(curtask, delta_exec);
    }
    //account_cfs_rq_runtime(cfs_rq, delta_exec);
}

static void __clear_buddies_last(struct sched_entity *se)
{
    for_each_sched_entity(se) {
        struct cfs_rq *cfs_rq = cfs_rq_of(se);
        if (cfs_rq->last != se)
            break;

        cfs_rq->last = NULL;
    }
}

static void __clear_buddies_next(struct sched_entity *se)
{
    for_each_sched_entity(se) {
        struct cfs_rq *cfs_rq = cfs_rq_of(se);
        if (cfs_rq->next != se)
            break;

        cfs_rq->next = NULL;
    }
}

static void __clear_buddies_skip(struct sched_entity *se)
{
    for_each_sched_entity(se) {
        struct cfs_rq *cfs_rq = cfs_rq_of(se);
        if (cfs_rq->skip != se)
            break;

        cfs_rq->skip = NULL;
    }
}

static void clear_buddies(struct cfs_rq *cfs_rq,
                          struct sched_entity *se)
{
    if (cfs_rq->last == se)
        __clear_buddies_last(se);

    if (cfs_rq->next == se)
        __clear_buddies_next(se);

    if (cfs_rq->skip == se)
        __clear_buddies_skip(se);
}

static void update_cfs_group(struct sched_entity *se)
{
    struct cfs_rq *gcfs_rq = group_cfs_rq(se);
    long shares;

    if (!gcfs_rq)
        return;

#if 0
    if (throttled_hierarchy(gcfs_rq))
        return;

    shares = calc_group_shares(gcfs_rq);

    reweight_entity(cfs_rq_of(se), se, shares);
#endif
    panic("%s: NO implementation!", __func__);
}

static inline void
update_stats_dequeue_fair(struct cfs_rq *cfs_rq, struct sched_entity *se,
                          int flags)
{
    if (!schedstat_enabled())
        return;

    panic("%s: NO implementation!", __func__);
}

static inline
struct cfs_bandwidth *tg_cfs_bandwidth(struct task_group *tg)
{
    return &tg->cfs_bandwidth;
}

/* we know any runtime found here is valid as update_curr() precedes return */
static void __return_cfs_rq_runtime(struct cfs_rq *cfs_rq)
{
    struct cfs_bandwidth *cfs_b = tg_cfs_bandwidth(cfs_rq->tg);
    s64 slack_runtime = cfs_rq->runtime_remaining - min_cfs_rq_runtime;

    if (slack_runtime <= 0)
        return;

    panic("%s: NO implementation!", __func__);
}

static __always_inline void return_cfs_rq_runtime(struct cfs_rq *cfs_rq)
{
    if (!cfs_bandwidth_used())
        return;

    if (!cfs_rq->runtime_enabled || cfs_rq->nr_running)
        return;

    __return_cfs_rq_runtime(cfs_rq);
}

static void
dequeue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se,
               int flags)
{
    /*
     * Update run-time statistics of the 'current'.
     */
    update_curr(cfs_rq);

    /*
     * When dequeuing a sched_entity, we must:
     *   - Update loads to have both entity and cfs_rq synced with now.
     *   - Subtract its load from the cfs_rq->runnable_avg.
     *   - Subtract its previous weight from cfs_rq->load.weight.
     *   - For group entity, update its weight to reflect the new share
     *     of its group cfs_rq.
     */
    update_load_avg(cfs_rq, se, UPDATE_TG);
    se_update_runnable(se);

    update_stats_dequeue_fair(cfs_rq, se, flags);

    clear_buddies(cfs_rq, se);

    if (se != cfs_rq->curr)
        __dequeue_entity(cfs_rq, se);

    se->on_rq = 0;
    account_entity_dequeue(cfs_rq, se);

    /*
     * Normalize after update_curr(); which will also have moved
     * min_vruntime if @se is the one holding it back. But before doing
     * update_min_vruntime() again, which will discount @se's position and
     * can move min_vruntime forward still more.
     */
    if (!(flags & DEQUEUE_SLEEP))
        se->vruntime -= cfs_rq->min_vruntime;

    /* return excess runtime on last dequeue */
    return_cfs_rq_runtime(cfs_rq);

    update_cfs_group(se);

    /*
     * Now advance min_vruntime if @se was the entity holding it back,
     * except when: DEQUEUE_SAVE && !DEQUEUE_MOVE, in this case we'll be
     * put back on, and if we advance min_vruntime, we'll be placed back
     * further than we started -- ie. we'll be penalized.
     */
    if ((flags & (DEQUEUE_SAVE | DEQUEUE_MOVE)) != DEQUEUE_SAVE)
        update_min_vruntime(cfs_rq);
}

static inline unsigned long task_util(struct task_struct *p)
{
    return READ_ONCE(p->se.avg.util_avg);
}

#define UTIL_EST_MARGIN (SCHED_CAPACITY_SCALE / 100)

/*
 * Check if a (signed) value is within a specified (unsigned) margin,
 * based on the observation that:
 *
 *     abs(x) < y := (unsigned)(x + y - 1) < (2 * y - 1)
 *
 * NOTE: this only works when value + margin < INT_MAX.
 */
static inline bool within_margin(int value, int margin)
{
    return ((unsigned int)(value + margin - 1) < (2 * margin - 1));
}

static inline void util_est_update(struct cfs_rq *cfs_rq,
                                   struct task_struct *p,
                                   bool task_sleep)
{
    long last_ewma_diff, last_enqueued_diff;
    struct util_est ue;

    if (!sched_feat(UTIL_EST))
        return;

    /*
     * Skip update of task's estimated utilization when the task has not
     * yet completed an activation, e.g. being migrated.
     */
    if (!task_sleep)
        return;

    /*
     * If the PELT values haven't changed since enqueue time,
     * skip the util_est update.
     */
    ue = p->se.avg.util_est;
    if (ue.enqueued & UTIL_AVG_UNCHANGED)
        return;

    last_enqueued_diff = ue.enqueued;

    /*
     * Reset EWMA on utilization increases, the moving average is used only
     * to smooth utilization decreases.
     */
    ue.enqueued = task_util(p);
    if (sched_feat(UTIL_EST_FASTUP)) {
        if (ue.ewma < ue.enqueued) {
            ue.ewma = ue.enqueued;
            goto done;
        }
    }

    /*
     * Skip update of task's estimated utilization when its members are
     * already ~1% close to its last activation value.
     */
    last_ewma_diff = ue.enqueued - ue.ewma;
    last_enqueued_diff -= ue.enqueued;
    if (within_margin(last_ewma_diff, UTIL_EST_MARGIN)) {
        if (!within_margin(last_enqueued_diff, UTIL_EST_MARGIN))
            goto done;

        return;
    }

    /*
     * To avoid overestimation of actual task utilization, skip updates if
     * we cannot grant there is idle time in this CPU.
     */
    if (task_util(p) > capacity_orig_of(cpu_of(rq_of(cfs_rq))))
        return;

    /*
     * Update Task's estimated utilization
     *
     * When *p completes an activation we can consolidate another sample
     * of the task size. This is done by storing the current PELT value
     * as ue.enqueued and by using this value to update the Exponential
     * Weighted Moving Average (EWMA):
     *
     *  ewma(t) = w *  task_util(p) + (1-w) * ewma(t-1)
     *          = w *  task_util(p) +         ewma(t-1)  - w * ewma(t-1)
     *          = w * (task_util(p) -         ewma(t-1)) +     ewma(t-1)
     *          = w * (      last_ewma_diff            ) +     ewma(t-1)
     *          = w * (last_ewma_diff  +  ewma(t-1) / w)
     *
     * Where 'w' is the weight of new samples, which is configured to be
     * 0.25, thus making w=1/4 ( >>= UTIL_EST_WEIGHT_SHIFT)
     */
    ue.ewma <<= UTIL_EST_WEIGHT_SHIFT;
    ue.ewma  += last_ewma_diff;
    ue.ewma >>= UTIL_EST_WEIGHT_SHIFT;

    panic("%s: NO implementation!", __func__);

 done:
    ue.enqueued |= UTIL_AVG_UNCHANGED;
    WRITE_ONCE(p->se.avg.util_est, ue);
}

static void set_next_buddy(struct sched_entity *se)
{
    for_each_sched_entity(se) {
        if (SCHED_WARN_ON(!se->on_rq))
            return;
        if (se_is_idle(se))
            return;
        cfs_rq_of(se)->next = se;
    }
}

/*
 * The dequeue_task method is called before nr_running is
 * decreased. We remove the task from the rbtree and
 * update the fair scheduling stats:
 */
static void dequeue_task_fair(struct rq *rq, struct task_struct *p,
                              int flags)
{
    struct cfs_rq *cfs_rq;
    struct sched_entity *se = &p->se;
    int task_sleep = flags & DEQUEUE_SLEEP;
    int idle_h_nr_running = task_has_idle_policy(p);
    bool was_sched_idle = sched_idle_rq(rq);

    util_est_dequeue(&rq->cfs, p);

    for_each_sched_entity(se) {
        cfs_rq = cfs_rq_of(se);
        dequeue_entity(cfs_rq, se, flags);

        cfs_rq->h_nr_running--;
        cfs_rq->idle_h_nr_running -= idle_h_nr_running;

        if (cfs_rq_is_idle(cfs_rq))
            idle_h_nr_running = 1;

        /* end evaluation on encountering a throttled cfs_rq */
        if (cfs_rq_throttled(cfs_rq))
            goto dequeue_throttle;

        /* Don't dequeue parent if it has other entities besides us */
        if (cfs_rq->load.weight) {
            /* Avoid re-evaluating load for this entity: */
            se = parent_entity(se);
            /*
             * Bias pick_next to pick a task from this cfs_rq, as
             * p is sleeping when it is within its sched_slice.
             */
            if (task_sleep && se && !throttled_hierarchy(cfs_rq))
                set_next_buddy(se);
            break;
        }
        flags |= DEQUEUE_SLEEP;
    }

    for_each_sched_entity(se) {
        cfs_rq = cfs_rq_of(se);

        update_load_avg(cfs_rq, se, UPDATE_TG);
        se_update_runnable(se);
        update_cfs_group(se);

        cfs_rq->h_nr_running--;
        cfs_rq->idle_h_nr_running -= idle_h_nr_running;

        if (cfs_rq_is_idle(cfs_rq))
            idle_h_nr_running = 1;

        /* end evaluation on encountering a throttled cfs_rq */
        if (cfs_rq_throttled(cfs_rq))
            goto dequeue_throttle;

    }

    /* At this point se is NULL and we are at root level*/
    sub_nr_running(rq, 1);

    /* balance early to pull high priority tasks */
    if (unlikely(!was_sched_idle && sched_idle_rq(rq)))
        rq->next_balance = jiffies;

 dequeue_throttle:
    util_est_update(&rq->cfs, p, task_sleep);
    hrtick_update(rq);
}

/*
 * Called within set_task_rq() right before setting a task's CPU. The
 * caller only guarantees p->pi_lock is held; no other assumptions,
 * including the state of rq->lock, should be made.
 */
void set_task_rq_fair(struct sched_entity *se,
                      struct cfs_rq *prev, struct cfs_rq *next)
{
    u64 p_last_update_time;
    u64 n_last_update_time;

    if (!sched_feat(ATTACH_AGE_LOAD))
        return;

    /*
     * We are supposed to update the task to "current" time, then its up to
     * date and ready to go to new CPU/cfs_rq. But we have difficulty in
     * getting what current time is, so simply throw away the out-of-date
     * time. This will result in the wakee task is less decayed, but giving
     * the wakee more load sounds not bad.
     */
    if (!(se->avg.last_update_time && prev))
        return;

#if 0
    p_last_update_time = prev->avg.last_update_time;
    n_last_update_time = next->avg.last_update_time;

    __update_load_avg_blocked_se(p_last_update_time, se);
    se->avg.last_update_time = n_last_update_time;
#endif
    panic("%s: END!\n", __func__);
}

static int wake_affine(struct sched_domain *sd, struct task_struct *p,
                       int this_cpu, int prev_cpu, int sync)
{
    panic("%s: END!", __func__);
}

static inline
int find_idlest_cpu(struct sched_domain *sd, struct task_struct *p,
                    int cpu, int prev_cpu, int sd_flag)
{
    panic("%s: END!\n", __func__);
}

/*
 * Try and locate an idle core/thread in the LLC cache domain.
 */
static int select_idle_sibling(struct task_struct *p, int prev,
                               int target)
{
    panic("%s: END!\n", __func__);
}

/*
 * select_task_rq_fair: Select target runqueue for the waking task in domains
 * that have the relevant SD flag set. In practice, this is SD_BALANCE_WAKE,
 * SD_BALANCE_FORK, or SD_BALANCE_EXEC.
 *
 * Balances load by selecting the idlest CPU in the idlest group, or under
 * certain conditions an idle sibling CPU if the domain has SD_WAKE_AFFINE set.
 *
 * Returns the target CPU number.
 */
static int
select_task_rq_fair(struct task_struct *p, int prev_cpu, int wake_flags)
{
    int sync = (wake_flags & WF_SYNC) && !(current->flags & PF_EXITING);
    struct sched_domain *tmp, *sd = NULL;
    int cpu = smp_processor_id();
    int new_cpu = prev_cpu;
    int want_affine = 0;
    /* SD_flags and WF_flags share the first nibble */
    int sd_flag = wake_flags & 0xF;

    /*
     * required for stable ->cpus_allowed
     */
    if (wake_flags & WF_TTWU) {
#if 0
        record_wakee(p);

        if (sched_energy_enabled()) {
            new_cpu = find_energy_efficient_cpu(p, prev_cpu);
            if (new_cpu >= 0)
                return new_cpu;
            new_cpu = prev_cpu;
        }

        want_affine = !wake_wide(p) && cpumask_test_cpu(cpu, p->cpus_ptr);
#endif
        panic("%s: WF_TTWU!", __func__);
    }

    rcu_read_lock();
    for_each_domain(cpu, tmp) {
        /*
         * If both 'cpu' and 'prev_cpu' are part of this domain,
         * cpu is a valid SD_WAKE_AFFINE target.
         */
        if (want_affine && (tmp->flags & SD_WAKE_AFFINE) &&
            cpumask_test_cpu(prev_cpu, sched_domain_span(tmp))) {
            if (cpu != prev_cpu)
                new_cpu = wake_affine(tmp, p, cpu, prev_cpu, sync);

            sd = NULL; /* Prefer wake_affine over balance flags */
            panic("%s: want_affine!", __func__);
            break;
        }

        /*
         * Usually only true for WF_EXEC and WF_FORK, as sched_domains
         * usually do not have SD_BALANCE_WAKE set. That means wakeup
         * will usually go to the fast path.
         */
        if (tmp->flags & sd_flag)
            sd = tmp;
        else if (!want_affine)
            break;
    }

    if (unlikely(sd)) {
        /* Slow path */
        new_cpu = find_idlest_cpu(sd, p, cpu, prev_cpu, sd_flag);
    } else if (wake_flags & WF_TTWU) { /* XXX always ? */
        /* Fast path */
        new_cpu = select_idle_sibling(p, prev_cpu, new_cpu);
    }
    rcu_read_unlock();

    return new_cpu;
}

void init_tg_cfs_entry(struct task_group *tg, struct cfs_rq *cfs_rq,
                       struct sched_entity *se, int cpu,
                       struct sched_entity *parent)
{
    struct rq *rq = cpu_rq(cpu);

    cfs_rq->tg = tg;
    cfs_rq->rq = rq;
    //init_cfs_rq_runtime(cfs_rq);

    tg->cfs_rq[cpu] = cfs_rq;
    tg->se[cpu] = se;

    /* se could be NULL for root_task_group */
    if (!se)
        return;

    panic("%s: END!\n", __func__);
}

static bool throttle_cfs_rq(struct cfs_rq *cfs_rq)
{
    struct rq *rq = rq_of(cfs_rq);
    struct cfs_bandwidth *cfs_b = tg_cfs_bandwidth(cfs_rq->tg);
    struct sched_entity *se;
    long task_delta, idle_task_delta, dequeue = 1;

    panic("%s: END!\n", __func__);
}

/* conditionally throttle active cfs_rq's from put_prev_entity() */
static bool check_cfs_rq_runtime(struct cfs_rq *cfs_rq)
{
    if (!cfs_bandwidth_used())
        return false;

    if (likely(!cfs_rq->runtime_enabled ||
               cfs_rq->runtime_remaining > 0))
        return false;

    /*
     * it's possible for a throttled entity to be forced into a running
     * state (e.g. set_curr_task), in this case we're finished.
     */
    if (cfs_rq_throttled(cfs_rq))
        return true;

    return throttle_cfs_rq(cfs_rq);
}

static inline void
update_stats_wait_start_fair(struct cfs_rq *cfs_rq,
                             struct sched_entity *se)
{
    struct sched_statistics *stats;
    struct task_struct *p = NULL;

    if (!schedstat_enabled())
        return;

    panic("%s: END!\n", __func__);
}

static void put_prev_entity(struct cfs_rq *cfs_rq,
                            struct sched_entity *prev)
{
    /*
     * If still on the runqueue then deactivate_task()
     * was not called and update_curr() has to be done:
     */
    if (prev->on_rq)
        update_curr(cfs_rq);

    /* throttle cfs_rqs exceeding runtime */
    check_cfs_rq_runtime(cfs_rq);

    if (prev->on_rq) {
        update_stats_wait_start_fair(cfs_rq, prev);
        /* Put 'current' back into the tree. */
        __enqueue_entity(cfs_rq, prev);
        /* in !on_rq case, update occurred at dequeue */
        update_load_avg(cfs_rq, prev, 0);
    }
    cfs_rq->curr = NULL;
}

/*
 * Account for a descheduled task:
 */
static void put_prev_task_fair(struct rq *rq, struct task_struct *prev)
{
    struct sched_entity *se = &prev->se;
    struct cfs_rq *cfs_rq;

    for_each_sched_entity(se) {
        cfs_rq = cfs_rq_of(se);
        put_prev_entity(cfs_rq, se);
    }
}

static inline void
update_stats_wait_end_fair(struct cfs_rq *cfs_rq,
                           struct sched_entity *se)
{
    struct sched_statistics *stats;
    struct task_struct *p = NULL;

    if (!schedstat_enabled())
        return;

    panic("%s: END!\n", __func__);
}

/**
 * update_cfs_rq_load_avg - update the cfs_rq's load/util averages
 * @now: current time, as per cfs_rq_clock_pelt()
 * @cfs_rq: cfs_rq to update
 *
 * The cfs_rq avg is the direct sum of all its entities (blocked and runnable)
 * avg. The immediate corollary is that all (fair) tasks must be attached, see
 * post_init_entity_util_avg().
 *
 * cfs_rq->avg is used for task_h_load() and update_cfs_share() for example.
 *
 * Return: true if the load decayed or we removed load.
 *
 * Since both these conditions indicate a changed cfs_rq->avg.load we should
 * call update_tg_load_avg() when this function returns true.
 */
static inline int
update_cfs_rq_load_avg(u64 now, struct cfs_rq *cfs_rq)
{
    unsigned long removed_load = 0, removed_util = 0,
                  removed_runnable = 0;
    struct sched_avg *sa = &cfs_rq->avg;
    int decayed = 0;

    if (cfs_rq->removed.nr) {
        panic("%s: 1!\n", __func__);
    }

    decayed |= __update_load_avg_cfs_rq(now, cfs_rq);

    return decayed;
}

/* Update task and its cfs_rq load average */
static inline int propagate_entity_load_avg(struct sched_entity *se)
{
    struct cfs_rq *cfs_rq, *gcfs_rq;

    if (entity_is_task(se))
        return 0;

    panic("%s: END!\n", __func__);
}

static inline void cfs_rq_util_change(struct cfs_rq *cfs_rq, int flags)
{
    struct rq *rq = rq_of(cfs_rq);

    if (&rq->cfs == cfs_rq) {
        /*
         * There are a few boundary cases this might miss but it should
         * get called often enough that that should (hopefully) not be
         * a real problem.
         *
         * It will not get called when we go idle, because the idle
         * thread is a different class (!fair), nor will the utilization
         * number include things like RT tasks.
         *
         * As is, the util number is not freq-invariant (we'd have to
         * implement arch_scale_freq_capacity() for that).
         *
         * See cpu_util_cfs().
         */
        cpufreq_update_util(rq, flags);
    }
}

/**
 * update_tg_load_avg - update the tg's load avg
 * @cfs_rq: the cfs_rq whose avg changed
 *
 * This function 'ensures': tg->load_avg := \Sum tg->cfs_rq[]->avg.load.
 * However, because tg->load_avg is a global value there are performance
 * considerations.
 *
 * In order to avoid having to look at the other cfs_rq's, we use a
 * differential update where we store the last value we propagated. This in
 * turn allows skipping updates if the differential is 'small'.
 *
 * Updating tg's load_avg is necessary before update_cfs_share().
 */
static inline void update_tg_load_avg(struct cfs_rq *cfs_rq)
{
    long delta = cfs_rq->avg.load_avg - cfs_rq->tg_load_avg_contrib;

    /*
     * No need to update load_avg for root_task_group as it is not used.
     */
    if (cfs_rq->tg == &root_task_group)
        return;

#if 0
    if (abs(delta) > cfs_rq->tg_load_avg_contrib / 64) {
        atomic_long_add(delta, &cfs_rq->tg->load_avg);
        cfs_rq->tg_load_avg_contrib = cfs_rq->avg.load_avg;
    }
#endif
    panic("%s: END!\n", __func__);
}

/* Update task and its cfs_rq load average */
static inline
void update_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se,
                     int flags)
{
    u64 now = cfs_rq_clock_pelt(cfs_rq);
    int decayed;

    /*
     * Track task load average for carrying it to new CPU
     * after migrated, and track group sched_entity load average
     * for task_h_load calc in migration
     */
    if (se->avg.last_update_time && !(flags & SKIP_AGE_LOAD))
        __update_load_avg_se(now, cfs_rq, se);

    decayed  = update_cfs_rq_load_avg(now, cfs_rq);
    decayed |= propagate_entity_load_avg(se);

    if (!se->avg.last_update_time && (flags & DO_ATTACH)) {

#if 0
        /*
         * DO_ATTACH means we're here from enqueue_entity().
         * !last_update_time means we've passed through
         * migrate_task_rq_fair() indicating we migrated.
         *
         * IOW we're enqueueing a task on a new CPU.
         */
        attach_entity_load_avg(cfs_rq, se);
        update_tg_load_avg(cfs_rq);
#endif
        panic("%s: 1!\n", __func__);

    } else if (decayed) {
        cfs_rq_util_change(cfs_rq, 0);

        if (flags & UPDATE_TG)
            update_tg_load_avg(cfs_rq);
    }
}

/*
 * We are picking a new current task - update its stats:
 */
static inline void
update_stats_curr_start(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    /*
     * We are starting a new run period:
     */
    se->exec_start = rq_clock_task(rq_of(cfs_rq));
}

static void
set_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    clear_buddies(cfs_rq, se);

    /* 'current' is not kept within the tree. */
    if (se->on_rq) {
        /*
         * Any task has to be enqueued before it get to execute on
         * a CPU. So account for the time it spent waiting on the
         * runqueue.
         */
        update_stats_wait_end_fair(cfs_rq, se);
        __dequeue_entity(cfs_rq, se);
        update_load_avg(cfs_rq, se, UPDATE_TG);
    }

    update_stats_curr_start(cfs_rq, se);
    cfs_rq->curr = se;
}

/* Account for a task changing its policy or group.
 *
 * This routine is mostly called to set cfs_rq->curr field when a task
 * migrates between groups/classes.
 */
static void set_next_task_fair(struct rq *rq, struct task_struct *p,
                               bool first)
{
    struct sched_entity *se = &p->se;

    if (task_on_rq_queued(p)) {
        /*
         * Move the next running task to the front of the list, so our
         * cfs_tasks list becomes MRU one.
         */
        list_move(&se->group_node, &rq->cfs_tasks);
    }

    for_each_sched_entity(se) {
        struct cfs_rq *cfs_rq = cfs_rq_of(se);

        set_next_entity(cfs_rq, se);
        /* ensure bandwidth has been allocated on our new cfs_rq */
        //account_cfs_rq_runtime(cfs_rq, 0);
    }
}

struct sched_entity *__pick_first_entity(struct cfs_rq *cfs_rq)
{
    struct rb_node *left = rb_first_cached(&cfs_rq->tasks_timeline);

    if (!left)
        return NULL;

    return __node_2_se(left);
}

/*
 * Pick the next process, keeping these things in mind, in this order:
 * 1) keep things fair between processes/task groups
 * 2) pick the "next" process, since someone really wants that to run
 * 3) pick the "last" process, for cache locality
 * 4) do not run the "skip" process, if something else is available
 */
static struct sched_entity *
pick_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
    struct sched_entity *se;
    struct sched_entity *left = __pick_first_entity(cfs_rq);

    /*
     * If curr is set we have to see if its left of the leftmost entity
     * still in the tree, provided there was anything in the tree at all.
     */
    if (!left || (curr && entity_before(curr, left)))
        left = curr;

    se = left; /* ideally we run the leftmost entity */

    return se;
}

static void hrtick_start_fair(struct rq *rq, struct task_struct *p)
{
    struct sched_entity *se = &p->se;
    struct cfs_rq *cfs_rq = cfs_rq_of(se);

    SCHED_WARN_ON(task_rq(p) != rq);

    if (rq->cfs.h_nr_running > 1) {
#if 0
        u64 slice = sched_slice(cfs_rq, se);
        u64 ran = se->sum_exec_runtime - se->prev_sum_exec_runtime;
        s64 delta = slice - ran;

        if (delta < 0) {
            if (task_current(rq, p))
                resched_curr(rq);
            return;
        }
        hrtick_start(rq, delta);
#endif
        panic("%s: END!\n", __func__);
    }
}

static inline
void update_misfit_status(struct task_struct *p, struct rq *rq)
{
    if (!static_branch_unlikely(&sched_asym_cpucapacity))
        return;

    if (!p || p->nr_cpus_allowed == 1) {
        rq->misfit_task_load = 0;
        return;
    }

#if 0
    if (task_fits_capacity(p, capacity_of(cpu_of(rq)))) {
        rq->misfit_task_load = 0;
        return;
    }

    /*
     * Make sure that misfit_task_load will not be null even if
     * task_h_load() returns 0.
     */
    rq->misfit_task_load = max_t(unsigned long, task_h_load(p), 1);
#endif
    panic("%s: END!\n", __func__);
}

struct task_struct *
pick_next_task_fair(struct rq *rq, struct task_struct *prev,
                    struct rq_flags *rf)
{
    int new_tasks;
    struct task_struct *p;
    struct sched_entity *se;
    struct cfs_rq *cfs_rq = &rq->cfs;

 again:
    if (!sched_fair_runnable(rq))
        goto idle;

    if (!prev || prev->sched_class != &fair_sched_class)
        goto simple;

    /*
     * Because of the set_next_buddy() in dequeue_task_fair() it is rather
     * likely that a next task is from the same cgroup as the current.
     *
     * Therefore attempt to avoid putting and setting the entire cgroup
     * hierarchy, only change the part that actually changes.
     */

    panic("%s: nr_running(%d) END!\n", __func__, rq->cfs.nr_running);

 simple:
    if (prev)
        put_prev_task(rq, prev);

    do {
        se = pick_next_entity(cfs_rq, NULL);
        set_next_entity(cfs_rq, se);
        cfs_rq = group_cfs_rq(se);
    } while (cfs_rq);

    p = task_of(se);

 done: __maybe_unused;
    /*
     * Move the next running task to the front of
     * the list, so our cfs_tasks list becomes MRU
     * one.
     */
    list_move(&p->se.group_node, &rq->cfs_tasks);

    if (hrtick_enabled_fair(rq))
        hrtick_start_fair(rq, p);

    update_misfit_status(p, rq);

    return p;

 idle:
    if (!rf)
        return NULL;

    new_tasks = newidle_balance(rq, rf);

    /*
     * Because newidle_balance() releases (and re-acquires) rq->lock, it is
     * possible for any higher priority task to appear. In that case we
     * must re-start the pick_next_entity() loop.
     */
    if (new_tasks < 0)
        return RETRY_TASK;

    panic("%s: ERR!\n", __func__);
}

static struct task_struct *__pick_next_task_fair(struct rq *rq)
{
    return pick_next_task_fair(rq, NULL, NULL);
}

void init_cfs_rq(struct cfs_rq *cfs_rq)
{
    cfs_rq->tasks_timeline = RB_ROOT_CACHED;
    cfs_rq->min_vruntime = (u64)(-(1LL << 20));
    raw_spin_lock_init(&cfs_rq->removed.lock);
}

static inline void
enqueue_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    cfs_rq->avg.load_avg += se->avg.load_avg;
    cfs_rq->avg.load_sum += se_weight(se) * se->avg.load_sum;
}

static inline void
dequeue_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    sub_positive(&cfs_rq->avg.load_avg, se->avg.load_avg);
    sub_positive(&cfs_rq->avg.load_sum, se_weight(se) * se->avg.load_sum);
    /* See update_cfs_rq_load_avg() */
    cfs_rq->avg.load_sum = max_t(u32, cfs_rq->avg.load_sum,
                      cfs_rq->avg.load_avg * PELT_MIN_DIVIDER);
}

static void reweight_entity(struct cfs_rq *cfs_rq, struct sched_entity *se,
                unsigned long weight)
{
    if (se->on_rq) {
        /* commit outstanding execution time */
        if (cfs_rq->curr == se)
            update_curr(cfs_rq);
        update_load_sub(&cfs_rq->load, se->load.weight);
    }
    dequeue_load_avg(cfs_rq, se);

    update_load_set(&se->load, weight);

    do {
        u32 divider = get_pelt_divider(&se->avg);

        se->avg.load_avg = div_u64(se_weight(se) * se->avg.load_sum,
                                   divider);
    } while (0);

    enqueue_load_avg(cfs_rq, se);
    if (se->on_rq)
        update_load_add(&cfs_rq->load, se->load.weight);
}

void reweight_task(struct task_struct *p, int prio)
{
    struct sched_entity *se = &p->se;
    struct cfs_rq *cfs_rq = cfs_rq_of(se);
    struct load_weight *load = &se->load;
    unsigned long weight = scale_load(sched_prio_to_weight[prio]);

    reweight_entity(cfs_rq, se, weight);
    load->inv_weight = sched_prio_to_wmult[prio];
}

__init void init_sched_fair_class(void)
{
#if 0
    open_softirq(SCHED_SOFTIRQ, run_rebalance_domains);

    nohz.next_balance = jiffies;
    nohz.next_blocked = jiffies;
    zalloc_cpumask_var(&nohz.idle_cpus_mask, GFP_NOWAIT);
#endif
    panic("%s: NO implementation!", __func__);
}

static void task_change_group_fair(struct task_struct *p, int type)
{
    panic("%s: NO implementation!", __func__);
}

static void update_curr_fair(struct rq *rq)
{
    update_curr(cfs_rq_of(&rq->curr->se));
}

/*
 * Increase the granularity value when there are more CPUs,
 * because with more CPUs the 'effective latency' as visible
 * to users decreases. But the relationship is not linear,
 * so pick a second-best guess by going with the log2 of the
 * number of CPUs.
 *
 * This idea comes from the SD scheduler of Con Kolivas:
 */
static unsigned int get_update_sysctl_factor(void)
{
    unsigned int cpus = min_t(unsigned int, num_online_cpus(), 8);
    unsigned int factor;

    switch (sysctl_sched_tunable_scaling) {
    case SCHED_TUNABLESCALING_NONE:
        factor = 1;
        break;
    case SCHED_TUNABLESCALING_LINEAR:
        factor = cpus;
        break;
    case SCHED_TUNABLESCALING_LOG:
    default:
        factor = 1 + ilog2(cpus);
        break;
    }

    return factor;
}

/* cpu online callback */
static void __maybe_unused update_runtime_enabled(struct rq *rq)
{
    struct task_group *tg;

    rcu_read_lock();
    list_for_each_entry_rcu(tg, &task_groups, list) {
        struct cfs_bandwidth *cfs_b = &tg->cfs_bandwidth;
        struct cfs_rq *cfs_rq = tg->cfs_rq[cpu_of(rq)];

        raw_spin_lock(&cfs_b->lock);
        cfs_rq->runtime_enabled = cfs_b->quota != RUNTIME_INF;
        raw_spin_unlock(&cfs_b->lock);
    }
    rcu_read_unlock();
}

static void update_sysctl(void)
{
#if 0
    unsigned int factor = get_update_sysctl_factor();

#define SET_SYSCTL(name) \
    (sysctl_##name = (factor) * normalized_sysctl_##name)
    SET_SYSCTL(sched_min_granularity);
    SET_SYSCTL(sched_latency);
    SET_SYSCTL(sched_wakeup_granularity);
#undef SET_SYSCTL
#endif
    panic("%s: NO implementation!", __func__);
}

static void rq_online_fair(struct rq *rq)
{
    //update_sysctl();

    update_runtime_enabled(rq);
}

static void task_dead_fair(struct task_struct *p)
{
    panic("%s: NO implementation!", __func__);
}

/*
 * sched_yield() is very simple
 *
 * The magic of dealing with the ->skip buddy is in pick_next_entity.
 */
static void yield_task_fair(struct rq *rq)
{
    panic("%s: NO implementation!", __func__);
}

static bool yield_to_task_fair(struct rq *rq, struct task_struct *p)
{
    panic("%s: NO implementation!", __func__);
}


/*
 * Called immediately before a task is migrated to a new CPU; task_cpu(p) and
 * cfs_rq_of(p) references at time of call are still valid and identify the
 * previous CPU. The caller guarantees p->pi_lock or task_rq(p)->lock is held.
 */
static void migrate_task_rq_fair(struct task_struct *p, int new_cpu)
{
    panic("%s: NO implementation!", __func__);
}

static struct task_struct *pick_task_fair(struct rq *rq)
{
    panic("%s: NO implementation!", __func__);
}

static void nohz_newidle_balance(struct rq *this_rq)
{
    int this_cpu = this_rq->cpu;

    /*
     * This CPU doesn't want to be disturbed by scheduler
     * housekeeping
     */
    if (!housekeeping_cpu(this_cpu, HK_TYPE_SCHED))
        return;

    /* Will wake up very soon. No time for doing anything else*/
    if (this_rq->avg_idle < sysctl_sched_migration_cost)
        return;

    /* Don't need to update blocked load of idle CPUs*/
    if (!READ_ONCE(nohz.has_blocked) ||
        time_before(jiffies, READ_ONCE(nohz.next_blocked)))
        return;

#if 0
    /*
     * Set the need to trigger ILB in order to update blocked load
     * before entering idle state.
     */
    atomic_or(NOHZ_NEWILB_KICK, nohz_flags(this_cpu));
#endif
    panic("%s: END!", __func__);
}

static inline void update_blocked_load_tick(struct rq *rq)
{
    WRITE_ONCE(rq->last_blocked_load_update_tick, jiffies);
}

static inline bool others_have_blocked(struct rq *rq)
{
    if (READ_ONCE(rq->avg_rt.util_avg))
        return true;

    if (READ_ONCE(rq->avg_dl.util_avg))
        return true;

    if (thermal_load_avg(rq))
        return true;

    return false;
}

static bool __update_blocked_others(struct rq *rq, bool *done)
{
    const struct sched_class *curr_class;
    u64 now = rq_clock_pelt(rq);
    unsigned long thermal_pressure;
    bool decayed;

    /*
     * update_load_avg() can call cpufreq_update_util(). Make sure that RT,
     * DL and IRQ signals have been updated before updating CFS.
     */
    curr_class = rq->curr->sched_class;

    thermal_pressure = arch_scale_thermal_pressure(cpu_of(rq));

    decayed =
        update_rt_rq_load_avg(now, rq, curr_class == &rt_sched_class) |
        update_dl_rq_load_avg(now, rq, curr_class == &dl_sched_class) |
        update_thermal_load_avg(rq_clock_thermal(rq), rq,
                                thermal_pressure) |
        update_irq_load_avg(rq, 0);

    if (others_have_blocked(rq))
        *done = false;

    return decayed;
}

/* Iterate thr' all leaf cfs_rq's on a runqueue */
#define for_each_leaf_cfs_rq_safe(rq, cfs_rq, pos)              \
    list_for_each_entry_safe(cfs_rq, pos, &rq->leaf_cfs_rq_list,\
                             leaf_cfs_rq_list)

/*
 * Check if we need to update the load and the utilization of a blocked
 * group_entity:
 */
static inline bool skip_blocked_update(struct sched_entity *se)
{
    struct cfs_rq *gcfs_rq = group_cfs_rq(se);

    /*
     * If sched_entity still have not zero load or utilization, we have to
     * decay it:
     */
    if (se->avg.load_avg || se->avg.util_avg)
        return false;

    /*
     * If there is a pending propagation, we have to update the load and
     * the utilization of the sched_entity:
     */
    if (gcfs_rq->propagate)
        return false;

    /*
     * Otherwise, the load and the utilization of the sched_entity is
     * already zero and there is no pending propagation, so it will be a
     * waste of time to try to decay it:
     */
    return true;
}

/*
 * Because list_add_leaf_cfs_rq always places a child cfs_rq on the list
 * immediately before a parent cfs_rq, and cfs_rqs are removed from the list
 * bottom-up, we only have to test whether the cfs_rq before us on the list
 * is our child.
 * If cfs_rq is not on the list, test whether a child needs its to be added to
 * connect a branch to the tree  * (see list_add_leaf_cfs_rq() for details).
 */
static inline bool child_cfs_rq_on_list(struct cfs_rq *cfs_rq)
{
    struct cfs_rq *prev_cfs_rq;
    struct list_head *prev;

    if (cfs_rq->on_list) {
        prev = cfs_rq->leaf_cfs_rq_list.prev;
    } else {
        struct rq *rq = rq_of(cfs_rq);

        prev = rq->tmp_alone_branch;
    }

    prev_cfs_rq = container_of(prev, struct cfs_rq, leaf_cfs_rq_list);

    return (prev_cfs_rq->tg->parent == cfs_rq->tg);
}

static inline bool cfs_rq_is_decayed(struct cfs_rq *cfs_rq)
{
    if (cfs_rq->load.weight)
        return false;

    if (cfs_rq->avg.load_sum)
        return false;

    if (cfs_rq->avg.util_sum)
        return false;

    if (cfs_rq->avg.runnable_sum)
        return false;

    if (child_cfs_rq_on_list(cfs_rq))
        return false;

    /*
     * _avg must be null when _sum are null because _avg = _sum / divider
     * Make sure that rounding and/or propagation of PELT values never
     * break this.
     */
    SCHED_WARN_ON(cfs_rq->avg.load_avg ||
                  cfs_rq->avg.util_avg ||
                  cfs_rq->avg.runnable_avg);

    return true;
}

static inline void list_del_leaf_cfs_rq(struct cfs_rq *cfs_rq)
{
    if (cfs_rq->on_list) {
        struct rq *rq = rq_of(cfs_rq);

        /*
         * With cfs_rq being unthrottled/throttled during an enqueue,
         * it can happen the tmp_alone_branch points the a leaf that
         * we finally want to del. In this case, tmp_alone_branch moves
         * to the prev element but it will point to rq->leaf_cfs_rq_list
         * at the end of the enqueue.
         */
        if (rq->tmp_alone_branch == &cfs_rq->leaf_cfs_rq_list)
            rq->tmp_alone_branch = cfs_rq->leaf_cfs_rq_list.prev;

        list_del_rcu(&cfs_rq->leaf_cfs_rq_list);
        cfs_rq->on_list = 0;
    }
}

static inline bool cfs_rq_has_blocked(struct cfs_rq *cfs_rq)
{
    if (cfs_rq->avg.load_avg)
        return true;

    if (cfs_rq->avg.util_avg)
        return true;

    return false;
}

static bool __update_blocked_fair(struct rq *rq, bool *done)
{
    struct cfs_rq *cfs_rq, *pos;
    bool decayed = false;
    int cpu = cpu_of(rq);

    /*
     * Iterates the task_group tree in a bottom up fashion, see
     * list_add_leaf_cfs_rq() for details.
     */
    for_each_leaf_cfs_rq_safe(rq, cfs_rq, pos) {
        struct sched_entity *se;

        if (update_cfs_rq_load_avg(cfs_rq_clock_pelt(cfs_rq), cfs_rq)) {
            update_tg_load_avg(cfs_rq);

            if (cfs_rq == &rq->cfs)
                decayed = true;
        }

        /* Propagate pending load changes to the parent, if any: */
        se = cfs_rq->tg->se[cpu];
        if (se && !skip_blocked_update(se))
            update_load_avg(cfs_rq_of(se), se, UPDATE_TG);

        /*
         * There can be a lot of idle CPU cgroups.  Don't let fully
         * decayed cfs_rqs linger on the list.
         */
        if (cfs_rq_is_decayed(cfs_rq))
            list_del_leaf_cfs_rq(cfs_rq);

        /* Don't need periodic decay once load/util_avg are null */
        if (cfs_rq_has_blocked(cfs_rq))
            *done = false;
    }

    return decayed;
}

static inline
void update_blocked_load_status(struct rq *rq, bool has_blocked)
{
    if (!has_blocked)
        rq->has_blocked_load = 0;
}

static void update_blocked_averages(int cpu)
{
    bool decayed = false, done = true;
    struct rq *rq = cpu_rq(cpu);
    struct rq_flags rf;

    rq_lock_irqsave(rq, &rf);
    update_blocked_load_tick(rq);
    update_rq_clock(rq);

    decayed |= __update_blocked_others(rq, &done);
    decayed |= __update_blocked_fair(rq, &done);

    update_blocked_load_status(rq, !done);
    if (decayed)
        cpufreq_update_util(rq, 0);
    rq_unlock_irqrestore(rq, &rf);
}

/*
 * newidle_balance is called by schedule() if this_cpu is about to become
 * idle. Attempts to pull tasks from other CPUs.
 *
 * Returns:
 *   < 0 - we released the lock and there are !fair tasks present
 *     0 - failed, no new tasks
 *   > 0 - success, new (fair) tasks present
 */
static int newidle_balance(struct rq *this_rq, struct rq_flags *rf)
{
    unsigned long next_balance = jiffies + HZ;
    int this_cpu = this_rq->cpu;
    u64 t0, t1, curr_cost = 0;
    struct sched_domain *sd;
    int pulled_task = 0;

    update_misfit_status(NULL, this_rq);

    /*
     * There is a task waiting to run. No need to search for one.
     * Return 0; the task will be enqueued when switching to idle.
     */
    if (this_rq->ttwu_pending)
        return 0;

    /*
     * We must set idle_stamp _before_ calling idle_balance(), such that we
     * measure the duration of idle_balance() as idle time.
     */
    this_rq->idle_stamp = rq_clock(this_rq);

    /*
     * Do not pull tasks towards !active CPUs...
     */
    if (!cpu_active(this_cpu))
        return 0;

    /*
     * This is OK, because current is on_cpu, which avoids it being picked
     * for load-balance and preemption/IRQs are still disabled avoiding
     * further scheduler activity on it and we're being very careful to
     * re-start the picking loop.
     */
    rq_unpin_lock(this_rq, rf);

    rcu_read_lock();
    sd = rcu_dereference_check_sched_domain(this_rq->sd);

    if (!READ_ONCE(this_rq->rd->overload) ||
        (sd && this_rq->avg_idle < sd->max_newidle_lb_cost)) {
        panic("%s: 1!", __func__);
    }
    rcu_read_unlock();

    raw_spin_rq_unlock(this_rq);

    t0 = sched_clock_cpu(this_cpu);
    update_blocked_averages(this_cpu);

    rcu_read_lock();
    for_each_domain(this_cpu, sd) {
        panic("%s: 1!", __func__);
    }
    rcu_read_unlock();

    raw_spin_rq_lock(this_rq);

    if (curr_cost > this_rq->max_idle_balance_cost)
        this_rq->max_idle_balance_cost = curr_cost;

    /*
     * While browsing the domains, we released the rq lock, a task could
     * have been enqueued in the meantime. Since we're not going idle,
     * pretend we pulled a task.
     */
    if (this_rq->cfs.h_nr_running && !pulled_task)
        pulled_task = 1;

    /* Is there a task of a high priority class? */
    if (this_rq->nr_running != this_rq->cfs.h_nr_running)
        pulled_task = -1;

 out:
    /* Move the next balance forward */
    if (time_after(this_rq->next_balance, next_balance))
        this_rq->next_balance = next_balance;

    if (pulled_task)
        this_rq->idle_stamp = 0;
    else
        nohz_newidle_balance(this_rq);

    rq_repin_lock(this_rq, rf);

    return pulled_task;
}

static int
balance_fair(struct rq *rq, struct task_struct *prev,
             struct rq_flags *rf)
{
    if (rq->nr_running)
        return 1;

    return newidle_balance(rq, rf) != 0;
}

static void set_last_buddy(struct sched_entity *se)
{
#if 0
    for_each_sched_entity(se) {
        if (SCHED_WARN_ON(!se->on_rq))
            return;
        if (se_is_idle(se))
            return;
        cfs_rq_of(se)->last = se;
    }
#endif
    panic("%s: END!", __func__);
}

/* Do the two (enqueued) entities belong to the same group ? */
static inline struct cfs_rq *
is_same_group(struct sched_entity *se, struct sched_entity *pse)
{
    if (se->cfs_rq == pse->cfs_rq)
        return se->cfs_rq;

    return NULL;
}

static void
find_matching_se(struct sched_entity **se, struct sched_entity **pse)
{
    int se_depth, pse_depth;

    /*
     * preemption test can be made between sibling entities who are in the
     * same cfs_rq i.e who have a common parent. Walk up the hierarchy of
     * both tasks until we find their ancestors who are siblings of common
     * parent.
     */

    /* First walk up until both entities are at same depth */
    se_depth = (*se)->depth;
    pse_depth = (*pse)->depth;

    while (se_depth > pse_depth) {
        se_depth--;
        *se = parent_entity(*se);
    }

    while (pse_depth > se_depth) {
        pse_depth--;
        *pse = parent_entity(*pse);
    }

    while (!is_same_group(*se, *pse)) {
        *se = parent_entity(*se);
        *pse = parent_entity(*pse);
    }
}

static unsigned long wakeup_gran(struct sched_entity *se)
{
    unsigned long gran = sysctl_sched_wakeup_granularity;

    /*
     * Since its curr running now, convert the gran from real-time
     * to virtual-time in his units.
     *
     * By using 'se' instead of 'curr' we penalize light tasks, so
     * they get preempted easier. That is, if 'se' < 'curr' then
     * the resulting gran will be larger, therefore penalizing the
     * lighter, if otoh 'se' > 'curr' then the resulting gran will
     * be smaller, again penalizing the lighter task.
     *
     * This is especially important for buddies when the leftmost
     * task is higher priority than the buddy.
     */
    return calc_delta_fair(gran, se);
}

/*
 * Should 'se' preempt 'curr'.
 *
 *             |s1
 *        |s2
 *   |s3
 *         g
 *      |<--->|c
 *
 *  w(c, s1) = -1
 *  w(c, s2) =  0
 *  w(c, s3) =  1
 *
 */
static int
wakeup_preempt_entity(struct sched_entity *curr, struct sched_entity *se)
{
    s64 gran, vdiff = curr->vruntime - se->vruntime;

    if (vdiff <= 0)
        return -1;

    gran = wakeup_gran(se);
    if (vdiff > gran)
        return 1;

    return 0;
}

/*
 * Preempt the current task with a newly woken task if needed:
 */
static void
check_preempt_wakeup(struct rq *rq, struct task_struct *p, int wake_flags)
{
    struct task_struct *curr = rq->curr;
    struct sched_entity *se = &curr->se, *pse = &p->se;
    struct cfs_rq *cfs_rq = task_cfs_rq(curr);
    int scale = cfs_rq->nr_running >= sched_nr_latency;
    int next_buddy_marked = 0;
    int cse_is_idle, pse_is_idle;

    if (unlikely(se == pse))
        return;

    /*
     * This is possible from callers such as attach_tasks(), in which we
     * unconditionally check_preempt_curr() after an enqueue (which may have
     * lead to a throttle).  This both saves work and prevents false
     * next-buddy nomination below.
     */
    if (unlikely(throttled_hierarchy(cfs_rq_of(pse))))
        return;

    if (sched_feat(NEXT_BUDDY) && scale && !(wake_flags & WF_FORK)) {
#if 0
        set_next_buddy(pse);
        next_buddy_marked = 1;
#endif
        panic("%s: 1!", __func__);
    }

    /*
     * We can come here with TIF_NEED_RESCHED already set from new task
     * wake up path.
     *
     * Note: this also catches the edge-case of curr being in a throttled
     * group (e.g. via set_curr_task), since update_curr() (in the
     * enqueue of curr) will have resulted in resched being set.  This
     * prevents us from potentially nominating it as a false LAST_BUDDY
     * below.
     */
    if (test_tsk_need_resched(curr))
        return;

    /* Idle tasks are by definition preempted by non-idle tasks. */
    if (unlikely(task_has_idle_policy(curr)) &&
        likely(!task_has_idle_policy(p)))
        goto preempt;

    /*
     * Batch and idle tasks do not preempt non-idle tasks (their preemption
     * is driven by the tick):
     */
    if (unlikely(p->policy != SCHED_NORMAL) || !sched_feat(WAKEUP_PREEMPTION))
        return;

    find_matching_se(&se, &pse);
    BUG_ON(!pse);

    cse_is_idle = se_is_idle(se);
    pse_is_idle = se_is_idle(pse);

    /*
     * Preempt an idle group in favor of a non-idle group (and don't preempt
     * in the inverse case).
     */
    if (cse_is_idle && !pse_is_idle)
        goto preempt;
    if (cse_is_idle != pse_is_idle)
        return;

    update_curr(cfs_rq_of(se));
    if (wakeup_preempt_entity(se, pse) == 1) {
        /*
         * Bias pick_next to pick the sched entity that is
         * triggering this preemption.
         */
        if (!next_buddy_marked)
            set_next_buddy(pse);
        goto preempt;
    }

    return;

 preempt:
    resched_curr(rq);
    /*
     * Only set the backward buddy when the current task is still
     * on the rq. This can happen when a wakeup gets interleaved
     * with schedule on the ->pre_schedule() or idle_balance()
     * point, either of which can * drop the rq lock.
     *
     * Also, during early boot the idle thread is in the fair class,
     * for obvious reasons its a bad idea to schedule back to it.
     */
    if (unlikely(!se->on_rq || curr == rq->idle))
        return;

    if (sched_feat(LAST_BUDDY) && scale && entity_is_task(se))
        set_last_buddy(se);
}

void unthrottle_cfs_rq(struct cfs_rq *cfs_rq)
{
    panic("%s: NO implementation!", __func__);
}

/* cpu offline callback */
static void __maybe_unused unthrottle_offline_cfs_rqs(struct rq *rq)
{
    struct task_group *tg;

    rcu_read_lock();
    list_for_each_entry_rcu(tg, &task_groups, list) {
        struct cfs_rq *cfs_rq = tg->cfs_rq[cpu_of(rq)];

        if (!cfs_rq->runtime_enabled)
            continue;

        /*
         * clock_task is not advancing so we just need to make sure
         * there's some valid quota amount
         */
        cfs_rq->runtime_remaining = 1;
        /*
         * Offline rq is schedulable till CPU is completely disabled
         * in take_cpu_down(), so we prevent new cfs throttling here.
         */
        cfs_rq->runtime_enabled = 0;

        if (cfs_rq_throttled(cfs_rq))
            unthrottle_cfs_rq(cfs_rq);
    }
    rcu_read_unlock();
}

static void rq_offline_fair(struct rq *rq)
{
    //update_sysctl();

    /* Ensure any throttled groups are reachable by pick_next_task */
    unthrottle_offline_cfs_rqs(rq);
}

/*
 * scheduler tick hitting a task of our scheduling class.
 *
 * NOTE: This function can be called remotely by the tick offload that
 * goes along full dynticks. Therefore no local assumption can be made
 * and everything must be accessed through the @rq and @curr passed in
 * parameters.
 */
static void task_tick_fair(struct rq *rq, struct task_struct *curr, int queued)
{
    panic("%s: NO implementation!", __func__);
}

static void switched_from_fair(struct rq *rq, struct task_struct *p)
{
    panic("%s: NO implementation!", __func__);
}

/*
 * called on fork with the child task as argument from the parent's context
 *  - child not yet on the tasklist
 *  - preemption disabled
 */
static void task_fork_fair(struct task_struct *p)
{
    panic("%s: NO implementation!", __func__);
}

/*
 * Priority of the task has changed. Check to see if we preempt
 * the current task.
 */
static void
prio_changed_fair(struct rq *rq, struct task_struct *p, int oldprio)
{
    if (!task_on_rq_queued(p))
        return;

    if (rq->cfs.nr_running == 1)
        return;

    panic("%s: NO implementation!", __func__);
}

static void switched_to_fair(struct rq *rq, struct task_struct *p)
{
    panic("%s: NO implementation!", __func__);
}

static unsigned int
get_rr_interval_fair(struct rq *rq, struct task_struct *task)
{
    panic("%s: NO implementation!", __func__);
}

/*
 * For asym packing, by default the lower numbered CPU has higher priority.
 */
int __weak arch_asym_cpu_priority(int cpu)
{
    return -cpu;
}

static unsigned long scale_rt_capacity(int cpu)
{
    struct rq *rq = cpu_rq(cpu);
    unsigned long max = arch_scale_cpu_capacity(cpu);
    unsigned long used, free;
    unsigned long irq;

    irq = cpu_util_irq(rq);

    if (unlikely(irq >= max))
        return 1;

    /*
     * avg_rt.util_avg and avg_dl.util_avg track binary signals
     * (running and not running) with weights 0 and 1024 respectively.
     * avg_thermal.load_avg tracks thermal pressure and the weighted
     * average uses the actual delta max capacity(load).
     */
    used = READ_ONCE(rq->avg_rt.util_avg);
    used += READ_ONCE(rq->avg_dl.util_avg);
    used += thermal_load_avg(rq);

    if (unlikely(used >= max))
        return 1;

    free = max - used;

    return scale_irq_capacity(free, irq, max);
}

static void update_cpu_capacity(struct sched_domain *sd, int cpu)
{
    unsigned long capacity = scale_rt_capacity(cpu);
    struct sched_group *sdg = sd->groups;

    cpu_rq(cpu)->cpu_capacity_orig = arch_scale_cpu_capacity(cpu);

    if (!capacity)
        capacity = 1;

    cpu_rq(cpu)->cpu_capacity = capacity;

    sdg->sgc->capacity = capacity;
    sdg->sgc->min_capacity = capacity;
    sdg->sgc->max_capacity = capacity;
}

void update_group_capacity(struct sched_domain *sd, int cpu)
{
    struct sched_domain *child = sd->child;
    struct sched_group *group, *sdg = sd->groups;
    unsigned long capacity, min_capacity, max_capacity;
    unsigned long interval;

    interval = msecs_to_jiffies(sd->balance_interval);
    interval = clamp(interval, 1UL, max_load_balance_interval);
    sdg->sgc->next_update = jiffies + interval;

    if (!child) {
        update_cpu_capacity(sd, cpu);
        return;
    }

    panic("%s: NO implementation!", __func__);
}

void __init sched_init_granularity(void)
{
    //update_sysctl();
}

/*
 * Internal function that runs load balance for all idle cpus. The load balance
 * can be a simple update of blocked load or a complete load balance with
 * tasks movement depending of flags.
 */
static void _nohz_idle_balance(struct rq *this_rq, unsigned int flags,
                               enum cpu_idle_type idle)
{
    panic("%s: NO implementation!", __func__);
}

/*
 * Check if we need to run the ILB for updating blocked load before entering
 * idle state.
 */
void nohz_run_idle_balance(int cpu)
{
    unsigned int flags;

    flags = atomic_fetch_andnot(NOHZ_NEWILB_KICK, nohz_flags(cpu));

    /*
     * Update the blocked load only if no SCHED_SOFTIRQ is about to happen
     * (ie NOHZ_STATS_KICK set) and will do the same.
     */
    if ((flags == NOHZ_NEWILB_KICK) && !need_resched())
        _nohz_idle_balance(cpu_rq(cpu), NOHZ_STATS_KICK, CPU_IDLE);
}

/*
 * All the scheduling class methods:
 */
DEFINE_SCHED_CLASS(fair) = {

    .enqueue_task       = enqueue_task_fair,
    .dequeue_task       = dequeue_task_fair,
    .yield_task         = yield_task_fair,
    .yield_to_task      = yield_to_task_fair,

    .check_preempt_curr = check_preempt_wakeup,

    .pick_next_task     = __pick_next_task_fair,
    .put_prev_task      = put_prev_task_fair,
    .set_next_task      = set_next_task_fair,

    .balance            = balance_fair,
    .pick_task          = pick_task_fair,
    .select_task_rq     = select_task_rq_fair,
    .migrate_task_rq    = migrate_task_rq_fair,

    .rq_online          = rq_online_fair,
    .rq_offline         = rq_offline_fair,

    .task_dead          = task_dead_fair,
    .set_cpus_allowed   = set_cpus_allowed_common,

    .task_tick          = task_tick_fair,
    .task_fork          = task_fork_fair,

    .prio_changed       = prio_changed_fair,
    .switched_from      = switched_from_fair,
    .switched_to        = switched_to_fair,

    .get_rr_interval    = get_rr_interval_fair,

    .update_curr        = update_curr_fair,

    .task_change_group  = task_change_group_fair,
};
