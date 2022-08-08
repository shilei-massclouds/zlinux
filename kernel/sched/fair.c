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
#include <linux/sched/clock.h>
#include <linux/sched/cond_resched.h>
#include <linux/sched/cputime.h>
#include <linux/sched/isolation.h>
#endif

#if 0
#include <linux/cpuidle.h>
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
#if 0
#include "stats.h"
#include "autogroup.h"
#endif

/* Walk up scheduling entities hierarchy */
#define for_each_sched_entity(se) \
    for (; se; se = se->parent)

#define __node_2_se(node) \
    rb_entry((node), struct sched_entity, run_node)

const_debug unsigned int sysctl_sched_migration_cost = 500000UL;

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

static void __dequeue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    rb_erase_cached(&se->run_node, &cfs_rq->tasks_timeline);
}

static void
account_entity_enqueue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
#if 0
    update_load_add(&cfs_rq->load, se->load.weight);

    if (entity_is_task(se)) {
        struct rq *rq = rq_of(cfs_rq);

        list_add(&se->group_node, &rq->cfs_tasks);
    }
#endif

    cfs_rq->nr_running++;
#if 0
    if (se_is_idle(se))
        cfs_rq->idle_nr_running++;
#endif
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
#if 0
    if (cfs_rq->nr_running == 1 || cfs_bandwidth_used())
        list_add_leaf_cfs_rq(cfs_rq);

    if (cfs_rq->nr_running == 1)
        check_enqueue_throttle(cfs_rq);
#endif
}

static int cfs_rq_is_idle(struct cfs_rq *cfs_rq)
{
    return cfs_rq->idle > 0;
}

static unsigned long capacity_of(int cpu)
{
    return cpu_rq(cpu)->cpu_capacity;
}

#if 0
static inline bool cpu_overutilized(int cpu)
{
    return !fits_capacity(cpu_util_cfs(cpu), capacity_of(cpu));
}
#endif

static inline void update_overutilized_status(struct rq *rq)
{
#if 0
    if (!READ_ONCE(rq->rd->overutilized) && cpu_overutilized(rq->cpu)) {
        WRITE_ONCE(rq->rd->overutilized, SG_OVERUTILIZED);
    }
#endif
}

static inline void assert_list_leaf_cfs_rq(struct rq *rq)
{
    SCHED_WARN_ON(rq->tmp_alone_branch != &rq->leaf_cfs_rq_list);
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

#if 0
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
#endif

    for_each_sched_entity(se) {
        if (se->on_rq)
            break;

        cfs_rq = cfs_rq_of(se);
        enqueue_entity(cfs_rq, se, flags);

        cfs_rq->h_nr_running++;
        cfs_rq->idle_h_nr_running += idle_h_nr_running;

        if (cfs_rq_is_idle(cfs_rq))
            idle_h_nr_running = 1;

#if 0
        /* end evaluation on encountering a throttled cfs_rq */
        if (cfs_rq_throttled(cfs_rq))
            goto enqueue_throttle;
#endif

        flags = ENQUEUE_WAKEUP;
    }

    printk("%s: 0 \n", __func__);
    for_each_sched_entity(se) {
        cfs_rq = cfs_rq_of(se);

        printk("%s: 1 \n", __func__);
        //update_load_avg(cfs_rq, se, UPDATE_TG);
        se_update_runnable(se);
        //update_cfs_group(se);

        printk("%s: 2 \n", __func__);
        cfs_rq->h_nr_running++;
        cfs_rq->idle_h_nr_running += idle_h_nr_running;

        if (cfs_rq_is_idle(cfs_rq))
            idle_h_nr_running = 1;

#if 0
        /* end evaluation on encountering a throttled cfs_rq */
        if (cfs_rq_throttled(cfs_rq))
            goto enqueue_throttle;

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
#if 0
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
#endif

    assert_list_leaf_cfs_rq(rq);

    //hrtick_update(rq);
}

/*
 * The dequeue_task method is called before nr_running is
 * decreased. We remove the task from the rbtree and
 * update the fair scheduling stats:
 */
static void dequeue_task_fair(struct rq *rq, struct task_struct *p, int flags)
{
    panic("%s: NO implementation!", __func__);
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

#if 0
    if (!sched_feat(ATTACH_AGE_LOAD))
        return;
#endif

#if 0
    /*
     * We are supposed to update the task to "current" time, then its up to
     * date and ready to go to new CPU/cfs_rq. But we have difficulty in
     * getting what current time is, so simply throw away the out-of-date
     * time. This will result in the wakee task is less decayed, but giving
     * the wakee more load sounds not bad.
     */
    if (!(se->avg.last_update_time && prev))
        return;

    p_last_update_time = prev->avg.last_update_time;
    n_last_update_time = next->avg.last_update_time;

    __update_load_avg_blocked_se(p_last_update_time, se);
    se->avg.last_update_time = n_last_update_time;
#endif
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
        panic("%s: WF_TTWU!", __func__);
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
    }

    rcu_read_lock();
    for_each_domain(cpu, tmp) {
        /*
         * If both 'cpu' and 'prev_cpu' are part of this domain,
         * cpu is a valid SD_WAKE_AFFINE target.
         */
#if 0
        if (want_affine && (tmp->flags & SD_WAKE_AFFINE) &&
            cpumask_test_cpu(prev_cpu, sched_domain_span(tmp))) {
            panic("%s: want_affine!", __func__);
            if (cpu != prev_cpu)
                new_cpu = wake_affine(tmp, p, cpu, prev_cpu, sync);

            sd = NULL; /* Prefer wake_affine over balance flags */
            break;
        }
#endif

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

#if 0
    if (unlikely(sd)) {
        /* Slow path */
        new_cpu = find_idlest_cpu(sd, p, cpu, prev_cpu, sd_flag);
    } else if (wake_flags & WF_TTWU) { /* XXX always ? */
        /* Fast path */
        new_cpu = select_idle_sibling(p, prev_cpu, new_cpu);
    }
#endif
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

static void put_prev_entity(struct cfs_rq *cfs_rq, struct sched_entity *prev)
{
#if 0
    /*
     * If still on the runqueue then deactivate_task()
     * was not called and update_curr() has to be done:
     */
    if (prev->on_rq)
        update_curr(cfs_rq);

    /* throttle cfs_rqs exceeding runtime */
    check_cfs_rq_runtime(cfs_rq);

    check_spread(cfs_rq, prev);
#endif

    if (prev->on_rq) {
#if 0
        update_stats_wait_start_fair(cfs_rq, prev);
#endif
        /* Put 'current' back into the tree. */
        __enqueue_entity(cfs_rq, prev);
#if 0
        /* in !on_rq case, update occurred at dequeue */
        update_load_avg(cfs_rq, prev, 0);
#endif
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

/* Account for a task changing its policy or group.
 *
 * This routine is mostly called to set cfs_rq->curr field when a task
 * migrates between groups/classes.
 */
static void set_next_task_fair(struct rq *rq, struct task_struct *p, bool first)
{
    panic("%s: END!\n", __func__);
}

static void
set_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
#if 0
    clear_buddies(cfs_rq, se);
#endif

    /* 'current' is not kept within the tree. */
    if (se->on_rq) {
        /*
         * Any task has to be enqueued before it get to execute on
         * a CPU. So account for the time it spent waiting on the
         * runqueue.
         */
        //update_stats_wait_end_fair(cfs_rq, se);
        __dequeue_entity(cfs_rq, se);
        //update_load_avg(cfs_rq, se, UPDATE_TG);
    }

    //update_stats_curr_start(cfs_rq, se);
    cfs_rq->curr = se;
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

#if 0
    if (hrtick_enabled_fair(rq))
        hrtick_start_fair(rq, p);

    update_misfit_status(p, rq);
#endif

    return p;

 idle:
    panic("%s: idle ...\n", __func__);
    if (!rf)
        return NULL;

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

void reweight_task(struct task_struct *p, int prio)
{
#if 0
    struct sched_entity *se = &p->se;
    struct cfs_rq *cfs_rq = cfs_rq_of(se);
    struct load_weight *load = &se->load;
    unsigned long weight = scale_load(sched_prio_to_weight[prio]);

    reweight_entity(cfs_rq, se, weight);
    load->inv_weight = sched_prio_to_wmult[prio];
#endif
    panic("%s: NO implementation!", __func__);
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

/*
 * All the scheduling class methods:
 */
DEFINE_SCHED_CLASS(fair) = {
    .enqueue_task       = enqueue_task_fair,
    .dequeue_task       = dequeue_task_fair,

    .pick_next_task     = __pick_next_task_fair,
    .put_prev_task      = put_prev_task_fair,
    .set_next_task      = set_next_task_fair,

    .select_task_rq     = select_task_rq_fair,
};
