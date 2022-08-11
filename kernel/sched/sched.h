/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Scheduler internal types and methods:
 */
#ifndef _KERNEL_SCHED_SCHED_H
#define _KERNEL_SCHED_SCHED_H

#include <linux/sched/deadline.h>
#include <linux/sched/rt.h>
#include <linux/sched/topology.h>
#if 0
#include <linux/sched/affinity.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/cpufreq.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/mm.h>
#include <linux/sched/rseq_api.h>
#include <linux/sched/signal.h>
#include <linux/sched/smt.h>
#include <linux/sched/stat.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/task_flags.h>
#endif
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/task.h>

#include <linux/bug.h>
#include <linux/bitmap.h>
#include <linux/jiffies.h>
#include <linux/ctype.h>
#include <linux/minmax.h>
#include <linux/rcupdate.h>
#include <linux/rcuwait.h>
#if 0
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cgroup_api.h>
#include <linux/cgroup.h>
#include <linux/cpufreq.h>
#include <linux/cpumask_api.h>
#include <linux/file.h>
#include <linux/fs_api.h>
#include <linux/hrtimer_api.h>
#include <linux/interrupt.h>
#include <linux/irq_work.h>
#include <linux/kref_api.h>
#include <linux/kthread.h>
#include <linux/lockdep_api.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/mutex_api.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/profile.h>
#include <linux/psi.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/softirq.h>
#include <linux/static_key.h>
#include <linux/syscalls_api.h>
#include <linux/syscalls.h>
#include <linux/tick.h>
#include <linux/u64_stats_sync_api.h>
#include <linux/uaccess.h>
#include <linux/workqueue_api.h>
#endif
#include <linux/stop_machine.h>
#include <linux/plist.h>
#include <linux/ktime_api.h>
#include <linux/wait_api.h>
#include <linux/wait_bit.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/topology.h>
#include <linux/spinlock_api.h>
#include <linux/slab.h>

//#include "../workqueue_internal.h"

//#include <linux/static_key.h>

#include "cpupri.h"
#include "cpudeadline.h"

#define SCA_CHECK           0x01
#define SCA_MIGRATE_DISABLE 0x02
#define SCA_MIGRATE_ENABLE  0x04
#define SCA_USER            0x08

#define SCHED_WARN_ON(x)   ({ (void)(x), 0; })

/* An entity is a task if it doesn't "own" a runqueue */
#define entity_is_task(se)  (!se->my_q)

/* task_struct::on_rq states: */
#define TASK_ON_RQ_QUEUED       1
#define TASK_ON_RQ_MIGRATING    2

DECLARE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

#define cpu_rq(cpu)     (&per_cpu(runqueues, (cpu)))
#define this_rq()       this_cpu_ptr(&runqueues)
#define task_rq(p)      cpu_rq(task_cpu(p))

#define sched_feat(x) !!(sysctl_sched_features & (1UL << __SCHED_FEAT_##x))

#define ENQUEUE_WAKEUP      0x01
#define ENQUEUE_RESTORE     0x02
#define ENQUEUE_NOCLOCK     0x08

#define ENQUEUE_MIGRATED    0x40

#define const_debug const

/*
 * Increase resolution of nice-level calculations for 64-bit architectures.
 * The extra resolution improves shares distribution and load balancing of
 * low-weight task groups (eg. nice +19 on an autogroup), deeper taskgroup
 * hierarchies, especially on larger systems. This is not a user-visible change
 * and does not change the user-interface for setting shares/weights.
 *
 * We increase resolution only if we have enough bits to allow this increased
 * resolution (i.e. 64-bit). The costs for increasing resolution when 32-bit
 * are pretty high and the returns do not justify the increased costs.
 *
 * Really only required when CONFIG_FAIR_GROUP_SCHED=y is also set, but to
 * increase coverage and consistency always enable it on 64-bit platforms.
 */
#define NICE_0_LOAD_SHIFT  (SCHED_FIXEDPOINT_SHIFT + SCHED_FIXEDPOINT_SHIFT)

/*
 * Task weight (visible to users) and its load (invisible to users) have
 * independent resolution, but they should be well calibrated. We use
 * scale_load() and scale_load_down(w) to convert between them. The
 * following must be true:
 *
 *  scale_load(sched_prio_to_weight[NICE_TO_PRIO(0)-MAX_RT_PRIO]) == NICE_0_LOAD
 *
 */
#define NICE_0_LOAD     (1L << NICE_0_LOAD_SHIFT)

#define ROOT_TASK_GROUP_LOAD    NICE_0_LOAD

/*
 * A weight of 0 or 1 can cause arithmetics problems.
 * A weight of a cfs_rq is the sum of weights of which entities
 * are queued on this cfs_rq, so a weight of a entity should not be
 * too large, so as the shares value of a task group.
 * (The default weight is 1024 - so there's no practical
 *  limitation from this.)
 */
#define MIN_SHARES      (1UL <<  1)
#define MAX_SHARES      (1UL << 18)

struct rt_bandwidth {
    /* nests inside the rq lock: */
    raw_spinlock_t      rt_runtime_lock;
    ktime_t             rt_period;
    u64                 rt_runtime;
    //struct hrtimer      rt_period_timer;
    unsigned int        rt_period_active;
};

/*
 * This is the priority-queue data structure of the RT scheduling class:
 */
struct rt_prio_array {
    DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
    struct list_head queue[MAX_RT_PRIO];
};

/* CFS-related fields in a runqueue */
struct cfs_rq {
    struct load_weight  load;
    unsigned int        nr_running;
    unsigned int        h_nr_running;      /* SCHED_{NORMAL,BATCH,IDLE} */
    unsigned int        idle_nr_running;   /* SCHED_IDLE */
    unsigned int        idle_h_nr_running; /* SCHED_IDLE */

    u64         exec_clock;
    u64         min_vruntime;

    struct rb_root_cached   tasks_timeline;

    /*
     * 'curr' points to currently running entity on this cfs_rq.
     * It is set to NULL otherwise (i.e when none are currently running).
     */
    struct sched_entity *curr;
    struct sched_entity *next;
    struct sched_entity *last;
    struct sched_entity *skip;

    /*
     * CFS load tracking
     */
    struct sched_avg    avg;
    struct {
        raw_spinlock_t  lock ____cacheline_aligned;
        int     nr;
        unsigned long   load_avg;
        unsigned long   util_avg;
        unsigned long   runnable_avg;
    } removed;

    unsigned long       tg_load_avg_contrib;
    long            propagate;
    long            prop_runnable_sum;

    /*
     *   h_load = weight * f(tg)
     *
     * Where f(tg) is the recursive weight fraction assigned to
     * this group.
     */
    unsigned long       h_load;
    u64         last_h_load_update;
    struct sched_entity *h_load_next;

    struct rq       *rq;    /* CPU runqueue to which this cfs_rq is attached */

    /*
     * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
     * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
     * (like users, containers etc.)
     *
     * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a CPU.
     * This list is used during load balance.
     */
    int         on_list;
    struct list_head    leaf_cfs_rq_list;
    struct task_group   *tg;    /* group that "owns" this runqueue */

    /* Locally cached copy of our task_group's idle value */
    int         idle;

#if 0
    int         runtime_enabled;
    s64         runtime_remaining;

    u64         throttled_clock;
    u64         throttled_clock_task;
    u64         throttled_clock_task_time;
    int         throttled;
    int         throttle_count;
    struct list_head    throttled_list;
#endif
};

/* Real-Time classes' related field in a runqueue: */
struct rt_rq {
    struct rt_prio_array    active;
    unsigned int        rt_nr_running;
    unsigned int        rr_nr_running;
    struct {
        int     curr; /* highest queued rt task prio */
        int     next; /* next highest */
    } highest_prio;
    unsigned int        rt_nr_migratory;
    unsigned int        rt_nr_total;
    int                 overloaded;
    struct plist_head   pushable_tasks;

    int         rt_queued;

    int         rt_throttled;
    u64         rt_time;
    u64         rt_runtime;
    /* Nests inside the rq lock: */
    raw_spinlock_t      rt_runtime_lock;
};

/* Deadline class' related fields in a runqueue */
struct dl_rq {
    /* runqueue is an rbtree, ordered by deadline */
    struct rb_root_cached   root;

    unsigned int        dl_nr_running;

    /*
     * Deadline values of the currently executing and the
     * earliest ready task on this rq. Caching these facilitates
     * the decision whether or not a ready but not running task
     * should migrate somewhere else.
     */
    struct {
        u64     curr;
        u64     next;
    } earliest_dl;

    unsigned int        dl_nr_migratory;
    int                 overloaded;

    /*
     * Tasks on this rq that can be pushed away. They are kept in
     * an rb-tree, ordered by tasks' deadlines, with caching
     * of the leftmost (earliest deadline) element.
     */
    struct rb_root_cached   pushable_dl_tasks_root;

    /*
     * "Active utilization" for this runqueue: increased when a
     * task wakes up (becomes TASK_RUNNING) and decreased when a
     * task blocks
     */
    u64         running_bw;

    /*
     * Utilization of the tasks "assigned" to this runqueue (including
     * the tasks that are in runqueue and the tasks that executed on this
     * CPU and blocked). Increased when a task moves to this runqueue, and
     * decreased when the task moves away (migrates, changes scheduling
     * policy, or terminates).
     * This is needed to compute the "inactive utilization" for the
     * runqueue (inactive utilization = this_bw - running_bw).
     */
    u64         this_bw;
    u64         extra_bw;

    /*
     * Inverse of the fraction of CPU utilization that can be reclaimed
     * by the GRUB algorithm.
     */
    u64         bw_ratio;
};

/*
 * This is the main, per-CPU runqueue data structure.
 *
 * Locking rule: those places that want to lock multiple runqueues
 * (such as the load balancing or the thread migration code), lock
 * acquire operations must be ordered by ascending &runqueue.
 */
struct rq {
    /* runqueue lock: */
    raw_spinlock_t      __lock;

    /*
     * nr_running and cpu_load should be in the same cacheline because
     * remote CPUs use both these fields when doing load calculation.
     */
    unsigned int        nr_running;

    unsigned long       last_blocked_load_update_tick;
    unsigned int        has_blocked_load;
    call_single_data_t  nohz_csd;
    unsigned int        nohz_tick_stopped;
    atomic_t            nohz_flags;

    unsigned int        ttwu_pending;

    u64                 nr_switches;

    struct cfs_rq       cfs;
    struct rt_rq        rt;
    struct dl_rq        dl;

    /* list of leaf cfs_rq on this CPU: */
    struct list_head    leaf_cfs_rq_list;
    struct list_head    *tmp_alone_branch;

    /*
     * This is part of a global counter where only the total sum
     * over all CPUs matters. A task can increase this counter on
     * one CPU and if it got migrated afterwards it may decrease
     * it on another CPU. Always updated under the runqueue lock:
     */
    unsigned int        nr_uninterruptible;

    struct task_struct __rcu    *curr;
    struct task_struct  *idle;
    struct task_struct  *stop;
    unsigned long       next_balance;
    struct mm_struct    *prev_mm;

    unsigned int        clock_update_flags;
    u64                 clock;
    /* Ensure that all clocks are in the same cache line */
    u64                 clock_task ____cacheline_aligned;
    u64                 clock_pelt;
    unsigned long       lost_idle_time;

    atomic_t            nr_iowait;

    int membarrier_state;

    struct root_domain      *rd;
    struct sched_domain __rcu   *sd;

    unsigned long       cpu_capacity;
    unsigned long       cpu_capacity_orig;

    struct callback_head    *balance_callback;

    unsigned char       nohz_idle_balance;
    unsigned char       idle_balance;

    unsigned long       misfit_task_load;

    /* For active balancing */
    int         active_balance;
    int         push_cpu;
    //struct cpu_stop_work    active_balance_work;

    /* CPU of this runqueue: */
    int         cpu;
    int         online;

    struct list_head cfs_tasks;

    struct sched_avg    avg_rt;
    struct sched_avg    avg_dl;

    u64 idle_stamp;
    u64 avg_idle;

    unsigned long   wake_stamp;
    u64             wake_avg_idle;

    /* This is used to determine avg_idle's max value */
    u64 max_idle_balance_cost;

    struct rcuwait  hotplug_wait;

    /* calc_load related fields */
    unsigned long       calc_load_update;
    long                calc_load_active;

    call_single_data_t  hrtick_csd;
    //struct hrtimer      hrtick_timer;
    ktime_t             hrtick_time;

    /* Must be inspected within a rcu lock section */
    struct cpuidle_state    *idle_state;

    unsigned int        nr_pinned;
    unsigned int        push_busy;
    //struct cpu_stop_work    push_work;
};

struct rq_flags {
    unsigned long flags;
};

struct sched_class {
    void (*enqueue_task) (struct rq *rq, struct task_struct *p, int flags);
    void (*dequeue_task) (struct rq *rq, struct task_struct *p, int flags);
    void (*yield_task)   (struct rq *rq);
    bool (*yield_to_task)(struct rq *rq, struct task_struct *p);

    void (*check_preempt_curr)(struct rq *rq, struct task_struct *p, int flags);

    struct task_struct *(*pick_next_task)(struct rq *rq);

    void (*put_prev_task)(struct rq *rq, struct task_struct *p);
    void (*set_next_task)(struct rq *rq, struct task_struct *p, bool first);

    int (*balance)(struct rq *rq, struct task_struct *prev,
                   struct rq_flags *rf);

    int  (*select_task_rq)(struct task_struct *p, int task_cpu, int flags);

    struct task_struct * (*pick_task)(struct rq *rq);

    void (*migrate_task_rq)(struct task_struct *p, int new_cpu);

    void (*task_woken)(struct rq *this_rq, struct task_struct *task);

    void (*set_cpus_allowed)(struct task_struct *p,
                             const struct cpumask *newmask,
                             u32 flags);

    void (*rq_online)(struct rq *rq);
    void (*rq_offline)(struct rq *rq);

    struct rq *(*find_lock_rq)(struct task_struct *p, struct rq *rq);

    void (*task_tick)(struct rq *rq, struct task_struct *p, int queued);
    void (*task_fork)(struct task_struct *p);
    void (*task_dead)(struct task_struct *p);

    /*
     * The switched_from() call is allowed to drop rq->lock, therefore we
     * cannot assume the switched_from/switched_to pair is serialized by
     * rq->lock. They are however serialized by p->pi_lock.
     */
    void (*switched_from)(struct rq *this_rq, struct task_struct *task);
    void (*switched_to)  (struct rq *this_rq, struct task_struct *task);
    void (*prio_changed) (struct rq *this_rq, struct task_struct *task,
                          int oldprio);

    unsigned int (*get_rr_interval)(struct rq *rq, struct task_struct *task);

    void (*update_curr)(struct rq *rq);

#define TASK_SET_GROUP      0
#define TASK_MOVE_GROUP     1

    void (*task_change_group)(struct task_struct *p, int type);
};

/* Task group related information */
struct task_group {
    /* schedulable entities of this group on each CPU */
    struct sched_entity **se;
    /* runqueue "owned" by this group on each CPU */
    struct cfs_rq       **cfs_rq;
    unsigned long       shares;

    struct list_head    list;

    struct task_group   *parent;
    struct list_head    siblings;
    struct list_head    children;
};

/*
 * We add the notion of a root-domain which will be used to define per-domain
 * variables. Each exclusive cpuset essentially defines an island domain by
 * fully partitioning the member CPUs from any other cpuset. Whenever a new
 * exclusive cpuset is created, we also create and attach a new root-domain
 * object.
 *
 */
struct root_domain {
    atomic_t        refcount;
    atomic_t        rto_count;
    struct rcu_head     rcu;
    cpumask_var_t       span;
    cpumask_var_t       online;

    /*
     * Indicate pullable load on at least one CPU, e.g:
     * - More than one runnable task
     * - Running task is misfit
     */
    int         overload;

    /* Indicate one or more cpus over-utilized (tipping point) */
    int         overutilized;

    /*
     * The bit corresponding to a CPU gets set here if such CPU has more
     * than one runnable -deadline task (as it is below for RT tasks).
     */
    cpumask_var_t       dlo_mask;
    atomic_t            dlo_count;
#if 0
    struct dl_bw        dl_bw;
#endif
    struct cpudl        cpudl;

    /*
     * Indicate whether a root_domain's dl_bw has been checked or
     * updated. It's monotonously increasing value.
     *
     * Also, some corner cases, like 'wrap around' is dangerous, but given
     * that u64 is 'big enough'. So that shouldn't be a concern.
     */
    u64 visit_gen;

    /*
     * The "RT overload" flag: it gets set if a CPU has more than
     * one runnable RT task.
     */
    cpumask_var_t       rto_mask;
    struct cpupri       cpupri;

    unsigned long       max_cpu_capacity;

    /*
     * NULL-terminated list of performance domains intersecting with the
     * CPUs of the rd. Protected by RCU.
     */
    struct perf_domain __rcu *pd;
};

extern void set_task_rq_fair(struct sched_entity *se,
                             struct cfs_rq *prev, struct cfs_rq *next);

static inline bool is_migration_disabled(struct task_struct *p)
{
    return p->migration_disabled;
}

static inline int task_on_rq_migrating(struct task_struct *p)
{
    return READ_ONCE(p->on_rq) == TASK_ON_RQ_MIGRATING;
}

extern void raw_spin_rq_lock_nested(struct rq *rq, int subclass);

static inline void raw_spin_rq_lock(struct rq *rq)
{
    raw_spin_rq_lock_nested(rq, 0);
}

static inline void raw_spin_rq_lock_irq(struct rq *rq)
{
    local_irq_disable();
    raw_spin_rq_lock(rq);
}

extern void raw_spin_rq_unlock(struct rq *rq);

static inline void raw_spin_rq_unlock_irq(struct rq *rq)
{
    raw_spin_rq_unlock(rq);
    local_irq_enable();
}

static inline unsigned long _raw_spin_rq_lock_irqsave(struct rq *rq)
{
    unsigned long flags;
    local_irq_save(flags);
    raw_spin_rq_lock(rq);
    return flags;
}

static inline void raw_spin_rq_unlock_irqrestore(struct rq *rq, unsigned long flags)
{
    raw_spin_rq_unlock(rq);
    local_irq_restore(flags);
}

#define raw_spin_rq_lock_irqsave(rq, flags) \
do {                                        \
    flags = _raw_spin_rq_lock_irqsave(rq);  \
} while (0)

static inline bool sched_core_enabled(struct rq *rq)
{
    return false;
}

static inline bool sched_core_disabled(void)
{
    return true;
}

/*
 * Be careful with this function; not for general use. The return value isn't
 * stable unless you actually hold a relevant rq->__lock.
 */
static inline raw_spinlock_t *rq_lockp(struct rq *rq)
{
    return &rq->__lock;
}

extern const struct sched_class stop_sched_class;
extern const struct sched_class dl_sched_class;
extern const struct sched_class rt_sched_class;
extern const struct sched_class fair_sched_class;
extern const struct sched_class idle_sched_class;

/*
 * Helper to define a sched_class instance; each one is placed in a separate
 * section which is ordered by the linker script:
 *
 *   include/asm-generic/vmlinux.lds.h
 *
 * Also enforce alignment on the instance, not the type, to guarantee layout.
 */
#define DEFINE_SCHED_CLASS(name) \
const struct sched_class name##_sched_class     \
    __aligned(__alignof__(struct sched_class))  \
    __section("__" #name "_sched_class")

#define rcu_dereference_check_sched_domain(p) rcu_dereference_check((p))

/*
 * The domain tree (rq->sd) is protected by RCU's quiescent state transition.
 * See destroy_sched_domains: call_rcu for details.
 *
 * The domain tree of any CPU may only be accessed from within
 * preempt-disabled sections.
 */
#define for_each_domain(cpu, __sd) \
    for (__sd = rcu_dereference_check_sched_domain(cpu_rq(cpu)->sd); \
            __sd; __sd = __sd->parent)

static inline int idle_policy(int policy)
{
    return policy == SCHED_IDLE;
}

static inline int task_has_idle_policy(struct task_struct *p)
{
    return idle_policy(p->policy);
}

/* runqueue on which this entity is (to be) queued */
static inline struct cfs_rq *cfs_rq_of(struct sched_entity *se)
{
    return se->cfs_rq;
}

/*
 * Return the group to which this tasks belongs.
 *
 * We cannot use task_css() and friends because the cgroup subsystem
 * changes that value before the cgroup_subsys::attach() method is called,
 * therefore we cannot pin it and might observe the wrong value.
 *
 * The same is true for autogroup's p->signal->autogroup->tg, the autogroup
 * core changes this before calling sched_move_task().
 *
 * Instead we use a 'copy' which is updated from sched_move_task() while
 * holding both task_struct::pi_lock and rq::lock.
 */
static inline struct task_group *task_group(struct task_struct *p)
{
    return p->sched_task_group;
}

/* Change a task's cfs_rq and parent entity if it moves across CPUs/groups */
static inline void set_task_rq(struct task_struct *p, unsigned int cpu)
{
    struct task_group *tg = task_group(p);

    set_task_rq_fair(&p->se, p->se.cfs_rq, tg->cfs_rq[cpu]);
    p->se.cfs_rq = tg->cfs_rq[cpu];
    p->se.parent = tg->se[cpu];
}

static inline void __set_task_cpu(struct task_struct *p, unsigned int cpu)
{
    set_task_rq(p, cpu);
    /*
     * After ->cpu is set up to a new value, task_rq_lock(p, ...) can be
     * successfully executed on another CPU. We must ensure that updates of
     * per-task data have been completed by this moment.
     */
    smp_wmb();
    WRITE_ONCE(task_thread_info(p)->cpu, cpu);
    p->wake_cpu = cpu;
}

extern void init_tg_cfs_entry(struct task_group *tg, struct cfs_rq *cfs_rq,
                              struct sched_entity *se, int cpu,
                              struct sched_entity *parent);

static inline void
rq_lock(struct rq *rq, struct rq_flags *rf)
    __acquires(rq->lock)
{
    raw_spin_rq_lock(rq);
}

static inline void put_prev_task(struct rq *rq, struct task_struct *prev)
{
    WARN_ON_ONCE(rq->curr != prev);
    prev->sched_class->put_prev_task(rq, prev);
}

/* Defined in include/asm-generic/vmlinux.lds.h */
extern struct sched_class __begin_sched_classes[];
extern struct sched_class __end_sched_classes[];

#define sched_class_highest (__end_sched_classes - 1)
#define sched_class_lowest  (__begin_sched_classes - 1)

#define for_class_range(class, _from, _to) \
    for (class = (_from); class != (_to); class--)

#define for_each_class(class) \
    for_class_range(class, sched_class_highest, sched_class_lowest)

static inline int task_on_rq_queued(struct task_struct *p)
{
    return p->on_rq == TASK_ON_RQ_QUEUED;
}

static inline bool sched_stop_runnable(struct rq *rq)
{
    return rq->stop && task_on_rq_queued(rq->stop);
}

static inline bool sched_dl_runnable(struct rq *rq)
{
    return rq->dl.dl_nr_running > 0;
}

static inline bool sched_rt_runnable(struct rq *rq)
{
    return rq->rt.rt_queued > 0;
}

static inline bool sched_fair_runnable(struct rq *rq)
{
    return rq->cfs.nr_running > 0;
}

static inline struct task_struct *task_of(struct sched_entity *se)
{
    SCHED_WARN_ON(!entity_is_task(se));
    return container_of(se, struct task_struct, se);
}

extern void rq_attach_root(struct rq *rq, struct root_domain *rd);

extern void init_defrootdomain(void);

extern void init_cfs_rq(struct cfs_rq *cfs_rq);
extern void init_rt_rq(struct rt_rq *rt_rq);
extern void init_dl_rq(struct dl_rq *dl_rq);

extern struct rt_bandwidth def_rt_bandwidth;
extern void init_rt_bandwidth(struct rt_bandwidth *rt_b, u64 period, u64 runtime);

extern void init_dl_bandwidth(struct dl_bandwidth *dl_b, u64 period, u64 runtime);
extern void init_dl_task_timer(struct sched_dl_entity *dl_se);
extern void init_dl_inactive_task_timer(struct sched_dl_entity *dl_se);

extern const_debug unsigned int sysctl_sched_nr_migrate;
extern const_debug unsigned int sysctl_sched_migration_cost;

extern void set_rq_online (struct rq *rq);
extern void set_rq_offline(struct rq *rq);
extern bool sched_smp_initialized;

/*
 * To aid in avoiding the subversion of "niceness" due to uneven distribution
 * of tasks with abnormal "nice" values across CPUs the contribution that
 * each task makes to its run queue's load is weighted according to its
 * scheduling class and "nice" value. For SCHED_NORMAL tasks this is just a
 * scaled version of the new time slice allocation that they receive on time
 * slice expiry etc.
 */

#define WEIGHT_IDLEPRIO     3
#define WMULT_IDLEPRIO      1431655765

#define scale_load(w)       ((w) << SCHED_FIXEDPOINT_SHIFT)
#define scale_load_down(w) \
({ \
    unsigned long __w = (w); \
    if (__w) \
        __w = max(2UL, __w >> SCHED_FIXEDPOINT_SHIFT); \
    __w; \
})

extern void reweight_task(struct task_struct *p, int prio);

extern __read_mostly int scheduler_running;

extern unsigned long calc_load_update;
extern atomic_long_t calc_load_tasks;

/*
 * Lockdep annotation that avoids accidental unlocks; it's like a
 * sticky/continuous lockdep_assert_held().
 *
 * This avoids code that has access to 'struct rq *rq' (basically everything in
 * the scheduler) from accidentally unlocking the rq if they do not also have a
 * copy of the (on-stack) 'struct rq_flags rf'.
 *
 * Also see Documentation/locking/lockdep-design.rst.
 */
static inline void rq_pin_lock(struct rq *rq, struct rq_flags *rf)
{
}

static inline void rq_unpin_lock(struct rq *rq, struct rq_flags *rf)
{
}

static inline void
rq_lock_irqsave(struct rq *rq, struct rq_flags *rf)
    __acquires(rq->lock)
{
    raw_spin_rq_lock_irqsave(rq, rf->flags);
    rq_pin_lock(rq, rf);
}

static inline void
rq_unlock_irqrestore(struct rq *rq, struct rq_flags *rf)
    __releases(rq->lock)
{
    rq_unpin_lock(rq, rf);
    raw_spin_rq_unlock_irqrestore(rq, rf->flags);
}

extern void init_sched_dl_class(void);
extern void init_sched_rt_class(void);
extern void init_sched_fair_class(void);

/*
 * rq::clock_update_flags bits
 *
 * %RQCF_REQ_SKIP - will request skipping of clock update on the next
 *  call to __schedule(). This is an optimisation to avoid
 *  neighbouring rq clock updates.
 *
 * %RQCF_ACT_SKIP - is set from inside of __schedule() when skipping is
 *  in effect and calls to update_rq_clock() are being ignored.
 *
 * %RQCF_UPDATED - is a debug flag that indicates whether a call has been
 *  made to update_rq_clock() since the last time rq::lock was pinned.
 *
 * If inside of __schedule(), clock_update_flags will have been
 * shifted left (a left shift is a cheap operation for the fast path
 * to promote %RQCF_REQ_SKIP to %RQCF_ACT_SKIP), so you must use,
 *
 *  if (rq-clock_update_flags >= RQCF_UPDATED)
 *
 * to check if %RQCF_UPDATED is set. It'll never be shifted more than
 * one position though, because the next rq_unpin_lock() will shift it
 * back.
 */
#define RQCF_REQ_SKIP       0x01
#define RQCF_ACT_SKIP       0x02
#define RQCF_UPDATED        0x04

struct rq *__task_rq_lock(struct task_struct *p, struct rq_flags *rf)
    __acquires(rq->lock);

struct rq *task_rq_lock(struct task_struct *p, struct rq_flags *rf)
    __acquires(p->pi_lock)
    __acquires(rq->lock);

static inline void __task_rq_unlock(struct rq *rq, struct rq_flags *rf)
    __releases(rq->lock)
{
    rq_unpin_lock(rq, rf);
    raw_spin_rq_unlock(rq);
}

static inline void
task_rq_unlock(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
    __releases(rq->lock)
    __releases(p->pi_lock)
{
    rq_unpin_lock(rq, rf);
    raw_spin_rq_unlock(rq);
    raw_spin_unlock_irqrestore(&p->pi_lock, rf->flags);
}

static inline void se_update_runnable(struct sched_entity *se)
{
    if (!entity_is_task(se))
        se->runnable_weight = se->my_q->h_nr_running;
}

static inline long se_runnable(struct sched_entity *se)
{
    if (entity_is_task(se))
        return !!se->on_rq;
    else
        return se->runnable_weight;
}

static inline void add_nr_running(struct rq *rq, unsigned count)
{
    unsigned prev_nr = rq->nr_running;

    rq->nr_running = prev_nr + count;

    if (prev_nr < 2 && rq->nr_running >= 2) {
        if (!READ_ONCE(rq->rd->overload))
            WRITE_ONCE(rq->rd->overload, 1);
    }
}

#endif /* _KERNEL_SCHED_SCHED_H */
