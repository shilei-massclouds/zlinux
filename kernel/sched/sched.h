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
#include <linux/ktime_api.h>
#include <linux/lockdep_api.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/mutex_api.h>
#include <linux/plist.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/profile.h>
#include <linux/psi.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/softirq.h>
#include <linux/static_key.h>
#include <linux/stop_machine.h>
#include <linux/syscalls_api.h>
#include <linux/syscalls.h>
#include <linux/tick.h>
#include <linux/u64_stats_sync_api.h>
#include <linux/uaccess.h>
#include <linux/wait_api.h>
#include <linux/wait_bit.h>
#include <linux/workqueue_api.h>
#endif
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/topology.h>
#include <linux/spinlock_api.h>

//#include "../workqueue_internal.h"

//#include <linux/static_key.h>

#if 0
#include "cpupri.h"
#include "cpudeadline.h"
#endif

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

#define ENQUEUE_WAKEUP      0x01
#define ENQUEUE_RESTORE     0x02
#define ENQUEUE_NOCLOCK     0x08

#define ENQUEUE_MIGRATED    0x40

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

/* CFS-related fields in a runqueue */
struct cfs_rq {
    unsigned int            nr_running;

    u64                     min_vruntime;

    struct rq *rq;          /* CPU runqueue to which this cfs_rq is attached */
    struct task_group *tg;  /* group that "owns" this runqueue */

    struct rb_root_cached   tasks_timeline;

    /*
     * 'curr' points to currently running entity on this cfs_rq.
     * It is set to NULL otherwise (i.e when none are currently running).
     */
    struct sched_entity *curr;

};

/* Deadline class' related fields in a runqueue */
struct dl_rq {
    /* runqueue is an rbtree, ordered by deadline */
    struct rb_root_cached   root;

    unsigned int        dl_nr_running;
};

/* Real-Time classes' related field in a runqueue: */
struct rt_rq {
    int         rt_queued;
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

    u64                 nr_switches;

    struct cfs_rq       cfs;
    struct rt_rq        rt;
    struct dl_rq        dl;

    /* calc_load related fields */
    unsigned long       calc_load_update;
    long                calc_load_active;

    struct task_struct __rcu    *curr;
    struct task_struct  *idle;
    struct task_struct  *stop;
    struct mm_struct    *prev_mm;

    struct list_head cfs_tasks;

    struct sched_domain __rcu *sd;
};

struct rq_flags {
    unsigned long flags;
};

struct sched_class {
    void (*enqueue_task)(struct rq *rq, struct task_struct *p, int flags);
    void (*dequeue_task) (struct rq *rq, struct task_struct *p, int flags);

    struct task_struct *(*pick_next_task)(struct rq *rq);

    void (*put_prev_task)(struct rq *rq, struct task_struct *p);
    void (*set_next_task)(struct rq *rq, struct task_struct *p, bool first);

    int (*select_task_rq)(struct task_struct *p, int task_cpu, int flags);
    struct task_struct * (*pick_task)(struct rq *rq);
    void (*task_woken)(struct rq *this_rq, struct task_struct *task);
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

static inline bool sched_core_enabled(struct rq *rq)
{
    return false;
}

static inline bool sched_core_disabled(void)
{
    return true;
}

static inline void
task_rq_unlock(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
    __releases(rq->lock)
    __releases(p->pi_lock)
{
    raw_spin_rq_unlock(rq);
    raw_spin_unlock_irqrestore(&p->pi_lock, rf->flags);
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

#endif /* _KERNEL_SCHED_SCHED_H */
