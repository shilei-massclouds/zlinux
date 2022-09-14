// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/workqueue.c - generic async execution with shared worker pool
 *
 * Copyright (C) 2002       Ingo Molnar
 *
 *   Derived from the taskqueue/keventd code by:
 *     David Woodhouse <dwmw2@infradead.org>
 *     Andrew Morton
 *     Kai Petzke <wpp@marie.physik.tu-berlin.de>
 *     Theodore Ts'o <tytso@mit.edu>
 *
 * Made to use alloc_percpu by Christoph Lameter.
 *
 * Copyright (C) 2010       SUSE Linux Products GmbH
 * Copyright (C) 2010       Tejun Heo <tj@kernel.org>
 *
 * This is the generic async execution mechanism.  Work items as are
 * executed in process context.  The worker pool is shared and
 * automatically managed.  There are two worker pools for each CPU (one for
 * normal work items and the other for high priority ones) and some extra
 * pools for workqueues which are not bound to any specific CPU - the
 * number of these backing pools is dynamic.
 *
 * Please read Documentation/core-api/workqueue.rst for details.
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/cpu.h>
//#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/hardirq.h>
#include <linux/mempolicy.h>
#if 0
#include <linux/freezer.h>
#include <linux/debug_locks.h>
#endif
#include <linux/lockdep.h>
#include <linux/idr.h>
//#include <linux/jhash.h>
#include <linux/hashtable.h>
#include <linux/rculist.h>
#include <linux/nodemask.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/sched/isolation.h>
#if 0
#include <linux/nmi.h>
#include <linux/kvm_para.h>
#endif
#include <linux/rcuwait.h>

#include "workqueue_internal.h"

/* see the comment above the definition of WQ_POWER_EFFICIENT */
static bool wq_power_efficient = false;

static bool wq_online;          /* can kworkers be created yet? */

static DEFINE_IDR(worker_pool_idr); /* PR: idr of all pools */

/* PL: allowable cpus for unbound wqs and work items */
static cpumask_var_t wq_unbound_cpumask;

static struct kmem_cache *pwq_cache;

/* wait for manager to go away */
static struct rcuwait manager_wait =
    __RCUWAIT_INITIALIZER(manager_wait);

struct workqueue_struct *system_wq __read_mostly;
EXPORT_SYMBOL(system_wq);
struct workqueue_struct *system_highpri_wq __read_mostly;
EXPORT_SYMBOL_GPL(system_highpri_wq);
struct workqueue_struct *system_long_wq __read_mostly;
EXPORT_SYMBOL_GPL(system_long_wq);
struct workqueue_struct *system_unbound_wq __read_mostly;
EXPORT_SYMBOL_GPL(system_unbound_wq);
struct workqueue_struct *system_freezable_wq __read_mostly;
EXPORT_SYMBOL_GPL(system_freezable_wq);
struct workqueue_struct *system_power_efficient_wq __read_mostly;
EXPORT_SYMBOL_GPL(system_power_efficient_wq);
struct workqueue_struct *system_freezable_power_efficient_wq
    __read_mostly;
EXPORT_SYMBOL_GPL(system_freezable_power_efficient_wq);

static bool wq_numa_enabled;        /* unbound NUMA affinity enabled */

/**
 * for_each_pool - iterate through all worker_pools in the system
 * @pool: iteration cursor
 * @pi: integer used for iteration
 *
 * This must be called either with wq_pool_mutex held or RCU read
 * locked.  If the pool needs to be used beyond the locking in effect, the
 * caller is responsible for guaranteeing that the pool stays online.
 *
 * The if/else clause exists only for the lockdep assertion and can be
 * ignored.
 */
#define for_each_pool(pool, pi)                     \
    idr_for_each_entry(&worker_pool_idr, pool, pi)  \

enum {
    /*
     * worker_pool flags
     *
     * A bound pool is either associated or disassociated with its CPU.
     * While associated (!DISASSOCIATED), all workers are bound to the
     * CPU and none has %WORKER_UNBOUND set and concurrency management
     * is in effect.
     *
     * While DISASSOCIATED, the cpu may be offline and all workers have
     * %WORKER_UNBOUND set and concurrency management disabled, and may
     * be executing on any CPU.  The pool behaves as an unbound one.
     *
     * Note that DISASSOCIATED should be flipped only while holding
     * wq_pool_attach_mutex to avoid changing binding state while
     * worker_attach_to_pool() is in progress.
     */
    POOL_MANAGER_ACTIVE = 1 << 0,   /* being managed */
    POOL_DISASSOCIATED  = 1 << 2,   /* cpu can't serve workers */

    /* worker flags */
    WORKER_DIE      = 1 << 1,   /* die die die */
    WORKER_IDLE     = 1 << 2,   /* is idle */
    WORKER_PREP     = 1 << 3,   /* preparing to run works */
    WORKER_CPU_INTENSIVE    = 1 << 6,   /* cpu intensive */
    WORKER_UNBOUND      = 1 << 7,   /* worker is unbound */
    WORKER_REBOUND      = 1 << 8,   /* worker was rebound */

    WORKER_NOT_RUNNING  = WORKER_PREP | WORKER_CPU_INTENSIVE |
                  WORKER_UNBOUND | WORKER_REBOUND,

    NR_STD_WORKER_POOLS = 2,        /* # standard pools per cpu */

    UNBOUND_POOL_HASH_ORDER = 6,        /* hashed by pool->attrs */
    BUSY_WORKER_HASH_ORDER  = 6,        /* 64 pointers */

    MAX_IDLE_WORKERS_RATIO  = 4,        /* 1/4 of busy can be idle */
    IDLE_WORKER_TIMEOUT = 300 * HZ, /* keep idle ones for 5 mins */

    MAYDAY_INITIAL_TIMEOUT  = HZ / 100 >= 2 ? HZ / 100 : 2,
                        /* call for help after 10ms
                           (min two ticks) */
    MAYDAY_INTERVAL     = HZ / 10,  /* and then every 100ms */
    CREATE_COOLDOWN     = HZ,       /* time to breath after fail */

    /*
     * Rescue workers are used only on emergencies and shared by
     * all cpus.  Give MIN_NICE.
     */
    RESCUER_NICE_LEVEL  = MIN_NICE,
    HIGHPRI_NICE_LEVEL  = MIN_NICE,

    WQ_NAME_LEN     = 24,
};

/* I: attributes used when instantiating standard unbound pools on demand */
static struct workqueue_attrs *
unbound_std_wq_attrs[NR_STD_WORKER_POOLS];

/* I: attributes used when instantiating ordered pools on demand */
static struct workqueue_attrs *ordered_wq_attrs[NR_STD_WORKER_POOLS];

/*
 * The per-pool workqueue.  While queued, the lower WORK_STRUCT_FLAG_BITS
 * of work_struct->data are used for flags and the remaining high bits
 * point to the pwq; thus, pwqs need to be aligned at two's power of the
 * number of flag bits.
 */
struct pool_workqueue {
    struct worker_pool  *pool;      /* I: the associated pool */
    struct workqueue_struct *wq;        /* I: the owning workqueue */
    int         work_color; /* L: current color */
    int         flush_color;    /* L: flushing color */
    int         refcnt;     /* L: reference count */
    int         nr_in_flight[WORK_NR_COLORS];
                        /* L: nr of in_flight works */

    /*
     * nr_active management and WORK_STRUCT_INACTIVE:
     *
     * When pwq->nr_active >= max_active, new work item is queued to
     * pwq->inactive_works instead of pool->worklist and marked with
     * WORK_STRUCT_INACTIVE.
     *
     * All work items marked with WORK_STRUCT_INACTIVE do not participate
     * in pwq->nr_active and all work items in pwq->inactive_works are
     * marked with WORK_STRUCT_INACTIVE.  But not all WORK_STRUCT_INACTIVE
     * work items are in pwq->inactive_works.  Some of them are ready to
     * run in pool->worklist or worker->scheduled.  Those work itmes are
     * only struct wq_barrier which is used for flush_work() and should
     * not participate in pwq->nr_active.  For non-barrier work item, it
     * is marked with WORK_STRUCT_INACTIVE iff it is in pwq->inactive_works.
     */
    int         nr_active;  /* L: nr of active works */
    int         max_active; /* L: max active works */
    struct list_head    inactive_works; /* L: inactive works */
    struct list_head    pwqs_node;  /* WR: node on wq->pwqs */
    struct list_head    mayday_node;    /* MD: node on wq->maydays */

    /*
     * Release of unbound pwq is punted to system_wq.  See put_pwq()
     * and pwq_unbound_release_workfn() for details.  pool_workqueue
     * itself is also RCU protected so that the first pwq can be
     * determined without grabbing wq->mutex.
     */
    struct work_struct  unbound_release_work;
    struct rcu_head     rcu;
} __aligned(1 << WORK_STRUCT_FLAG_BITS);

/*
 * Structure used to wait for workqueue flush.
 */
struct wq_flusher {
    struct list_head    list;       /* WQ: list of flushers */
    int         flush_color;    /* WQ: flush color waiting for */
    struct completion   done;       /* flush completion */
};

/*
 * The externally visible workqueue.  It relays the issued work items to
 * the appropriate worker_pool through its pool_workqueues.
 */
struct workqueue_struct {
    struct list_head    pwqs;       /* WR: all pwqs of this wq */
    struct list_head    list;       /* PR: list of all workqueues */

    struct mutex        mutex;      /* protects this wq */
    int         work_color; /* WQ: current work color */
    int         flush_color;    /* WQ: current flush color */
    atomic_t        nr_pwqs_to_flush; /* flush in progress */
    struct wq_flusher   *first_flusher; /* WQ: first flusher */
    struct list_head    flusher_queue;  /* WQ: flush waiters */
    struct list_head    flusher_overflow; /* WQ: flush overflow list */

    struct list_head    maydays;    /* MD: pwqs requesting rescue */
    struct worker       *rescuer;   /* MD: rescue worker */

    int         nr_drainers;    /* WQ: drain in progress */
    int         saved_max_active; /* WQ: saved pwq max_active */

    struct workqueue_attrs  *unbound_attrs; /* PW: only for unbound wqs */
    struct pool_workqueue   *dfl_pwq;   /* PW: only for unbound wqs */

    struct wq_device    *wq_dev;    /* I: for sysfs interface */
    char            name[WQ_NAME_LEN]; /* I: workqueue name */

    /*
     * Destruction of workqueue_struct is RCU protected to allow walking
     * the workqueues list without grabbing wq_pool_mutex.
     * This is used to dump all workqueues from sysrq.
     */
    struct rcu_head     rcu;

    /* hot fields used during command issue, aligned to cacheline */
    unsigned int        flags ____cacheline_aligned; /* WQ: WQ_* flags */
    struct pool_workqueue __percpu *cpu_pwqs; /* I: per-cpu pwqs */
    struct pool_workqueue __rcu *numa_pwq_tbl[]; /* PWR: unbound pwqs indexed by node */
};

static LIST_HEAD(workqueues);       /* PR: list of all workqueues */
static bool workqueue_freezing;     /* PL: have wqs started freezing? */

/* struct worker is defined in workqueue_internal.h */

struct worker_pool {
    raw_spinlock_t      lock;       /* the pool lock */
    int         cpu;        /* I: the associated cpu */
    int         node;       /* I: the associated node ID */
    int         id;     /* I: pool ID */
    unsigned int        flags;      /* X: flags */

    unsigned long       watchdog_ts;    /* L: watchdog timestamp */

    /*
     * The counter is incremented in a process context on the associated CPU
     * w/ preemption disabled, and decremented or reset in the same context
     * but w/ pool->lock held. The readers grab pool->lock and are
     * guaranteed to see if the counter reached zero.
     */
    int         nr_running;

    struct list_head    worklist;   /* L: list of pending works */

    int         nr_workers; /* L: total number of workers */
    int         nr_idle;    /* L: currently idle workers */

    struct list_head    idle_list;  /* L: list of idle workers */
    struct timer_list   idle_timer; /* L: worker idle timeout */
    struct timer_list   mayday_timer;   /* L: SOS timer for workers */


    /* a workers is either on busy_hash or idle_list, or the manager */
    DECLARE_HASHTABLE(busy_hash, BUSY_WORKER_HASH_ORDER);
                        /* L: hash of busy workers */

    struct worker       *manager;   /* L: purely informational */
    struct list_head    workers;    /* A: attached workers */
    struct completion   *detach_completion; /* all workers detached */

    struct ida      worker_ida; /* worker IDs for task name */

    struct workqueue_attrs  *attrs;     /* I: worker attributes */
    struct hlist_node   hash_node;  /* PL: unbound_pool_hash node */
    int         refcnt;     /* PL: refcnt for unbound pools */

    /*
     * Destruction of pool is RCU protected to allow dereferences
     * from get_work_pool().
     */
    struct rcu_head     rcu;
};

/* protects pools and workqueues list */
static DEFINE_MUTEX(wq_pool_mutex);
/* protects worker attach/detach */
static DEFINE_MUTEX(wq_pool_attach_mutex);

/* PL: hash of all unbound pools keyed by pool->attrs */
static DEFINE_HASHTABLE(unbound_pool_hash, UNBOUND_POOL_HASH_ORDER);

/* the per-cpu worker pools */
static DEFINE_PER_CPU_SHARED_ALIGNED(struct worker_pool [NR_STD_WORKER_POOLS], cpu_worker_pools);

#define for_each_cpu_worker_pool(pool, cpu)             \
    for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0];       \
         (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; \
         (pool)++)

static struct worker *create_worker(struct worker_pool *pool);

static int get_work_color(unsigned long work_data)
{
    return (work_data >> WORK_STRUCT_COLOR_SHIFT) &
        ((1 << WORK_STRUCT_COLOR_BITS) - 1);
}

/*
 * Policy functions.  These define the policies on how the global worker
 * pools are managed.  Unless noted otherwise, these functions assume that
 * they're being called with pool->lock held.
 */

static bool __need_more_worker(struct worker_pool *pool)
{
    return !pool->nr_running;
}

/* Can I start working?  Called from busy but !running workers. */
static bool may_start_working(struct worker_pool *pool)
{
    return pool->nr_idle;
}

/* Do I need to keep working?  Called from currently running workers. */
static bool keep_working(struct worker_pool *pool)
{
    return !list_empty(&pool->worklist) && (pool->nr_running <= 1);
}

/*
 * Need to wake up a worker?  Called from anything but currently
 * running workers.
 *
 * Note that, because unbound workers never contribute to nr_running, this
 * function will always return %true for unbound pools as long as the
 * worklist isn't empty.
 */
static bool need_more_worker(struct worker_pool *pool)
{
    return !list_empty(&pool->worklist) && __need_more_worker(pool);
}

/* Do we need a new worker?  Called from manager. */
static bool need_to_create_worker(struct worker_pool *pool)
{
    return need_more_worker(pool) && !may_start_working(pool);
}

static void wq_init_lockdep(struct workqueue_struct *wq)
{
}

static void wq_unregister_lockdep(struct workqueue_struct *wq)
{
}

static void wq_free_lockdep(struct workqueue_struct *wq)
{
}

static struct pool_workqueue *get_work_pwq(struct work_struct *work)
{
    unsigned long data = atomic_long_read(&work->data);

    if (data & WORK_STRUCT_PWQ)
        return (void *)(data & WORK_STRUCT_WQ_DATA_MASK);
    else
        return NULL;
}

/* Do we have too many workers and should some go away? */
static bool too_many_workers(struct worker_pool *pool)
{
    bool managing = pool->flags & POOL_MANAGER_ACTIVE;
    int nr_idle = pool->nr_idle + managing; /* manager is considered idle */
    int nr_busy = pool->nr_workers - nr_idle;

    return nr_idle > 2 && (nr_idle - 2) * MAX_IDLE_WORKERS_RATIO >= nr_busy;
}

/*
 * Test whether @work is being queued from another work executing on the
 * same workqueue.
 */
static bool is_chained_work(struct workqueue_struct *wq)
{
    struct worker *worker;

    worker = current_wq_worker();
    /*
     * Return %true iff I'm a worker executing a work item on @wq.  If
     * I'm @worker, it's safe to dereference it without locking.
     */
    return worker && worker->current_pwq->wq == wq;
}

/**
 * get_work_pool - return the worker_pool a given work was associated with
 * @work: the work item of interest
 *
 * Pools are created and destroyed under wq_pool_mutex, and allows read
 * access under RCU read lock.  As such, this function should be
 * called under wq_pool_mutex or inside of a rcu_read_lock() region.
 *
 * All fields of the returned pool are accessible as long as the above
 * mentioned locking is in effect.  If the returned pool needs to be used
 * beyond the critical section, the caller is responsible for ensuring the
 * returned pool is and stays online.
 *
 * Return: The worker_pool @work was last associated with.  %NULL if none.
 */
static struct worker_pool *get_work_pool(struct work_struct *work)
{
    unsigned long data = atomic_long_read(&work->data);
    int pool_id;

    if (data & WORK_STRUCT_PWQ)
        return ((struct pool_workqueue *)
            (data & WORK_STRUCT_WQ_DATA_MASK))->pool;

    pool_id = data >> WORK_OFFQ_POOL_SHIFT;
    if (pool_id == WORK_OFFQ_POOL_NONE)
        return NULL;

    return idr_find(&worker_pool_idr, pool_id);
}

static unsigned int work_color_to_flags(int color)
{
    return color << WORK_STRUCT_COLOR_SHIFT;
}


/*
 * While queued, %WORK_STRUCT_PWQ is set and non flag bits of a work's data
 * contain the pointer to the queued pwq.  Once execution starts, the flag
 * is cleared and the high bits contain OFFQ flags and pool ID.
 *
 * set_work_pwq(), set_work_pool_and_clear_pending(), mark_work_canceling()
 * and clear_work_data() can be used to set the pwq, pool or clear
 * work->data.  These functions should only be called while the work is
 * owned - ie. while the PENDING bit is set.
 *
 * get_work_pool() and get_work_pwq() can be used to obtain the pool or pwq
 * corresponding to a work.  Pool is available once the work has been
 * queued anywhere after initialization until it is sync canceled.  pwq is
 * available only while the work item is queued.
 *
 * %WORK_OFFQ_CANCELING is used to mark a work item which is being
 * canceled.  While being canceled, a work item may have its PENDING set
 * but stay off timer and worklist for arbitrarily long and nobody should
 * try to steal the PENDING bit.
 */
static inline
void set_work_data(struct work_struct *work, unsigned long data,
                   unsigned long flags)
{
    WARN_ON_ONCE(!work_pending(work));
    atomic_long_set(&work->data, data | flags | work_static(work));
}

/**
 * get_pwq - get an extra reference on the specified pool_workqueue
 * @pwq: pool_workqueue to get
 *
 * Obtain an extra reference on @pwq.  The caller should guarantee that
 * @pwq has positive refcnt and be holding the matching pool->lock.
 */
static void get_pwq(struct pool_workqueue *pwq)
{
    WARN_ON_ONCE(pwq->refcnt <= 0);
    pwq->refcnt++;
}

static void set_work_pwq(struct work_struct *work,
                         struct pool_workqueue *pwq,
                         unsigned long extra_flags)
{
    set_work_data(work, (unsigned long)pwq,
              WORK_STRUCT_PENDING | WORK_STRUCT_PWQ | extra_flags);
}

/*
 * Wake up functions.
 */

/* Return the first idle worker.  Called with pool->lock held. */
static struct worker *first_idle_worker(struct worker_pool *pool)
{
    if (unlikely(list_empty(&pool->idle_list)))
        return NULL;

    return list_first_entry(&pool->idle_list, struct worker, entry);
}

/**
 * wake_up_worker - wake up an idle worker
 * @pool: worker pool to wake worker from
 *
 * Wake up the first idle worker of @pool.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock).
 */
static void wake_up_worker(struct worker_pool *pool)
{
    struct worker *worker = first_idle_worker(pool);

    if (likely(worker))
        wake_up_process(worker->task);
}

/**
 * insert_work - insert a work into a pool
 * @pwq: pwq @work belongs to
 * @work: work to insert
 * @head: insertion point
 * @extra_flags: extra WORK_STRUCT_* flags to set
 *
 * Insert @work which belongs to @pwq after @head.  @extra_flags is or'd to
 * work_struct flags.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock).
 */
static void insert_work(struct pool_workqueue *pwq,
                        struct work_struct *work,
                        struct list_head *head,
                        unsigned int extra_flags)
{
    struct worker_pool *pool = pwq->pool;

    /* we own @work, set data and link */
    set_work_pwq(work, pwq, extra_flags);
    printk("%s: 2 work(%lx) head(%lx)\n", __func__, work, head);
    list_add_tail(&work->entry, head);
    printk("%s: 3\n", __func__);
    get_pwq(pwq);

    printk("%s: !\n", __func__);
    if (__need_more_worker(pool))
        wake_up_worker(pool);
}

static void __queue_work(int cpu, struct workqueue_struct *wq,
                         struct work_struct *work)
{
    struct pool_workqueue *pwq;
    struct worker_pool *last_pool;
    struct list_head *worklist;
    unsigned int work_flags;
    unsigned int req_cpu = cpu;

    /* if draining, only works from the same workqueue are allowed */
    if (unlikely(wq->flags & __WQ_DRAINING) &&
        WARN_ON_ONCE(!is_chained_work(wq)))
        return;
    rcu_read_lock();
 retry:
    /* pwq which will be used unless @work is executing elsewhere */
    if (wq->flags & WQ_UNBOUND) {
#if 0
        if (req_cpu == WORK_CPU_UNBOUND)
            cpu = wq_select_unbound_cpu(raw_smp_processor_id());
        pwq = unbound_pwq_by_node(wq, cpu_to_node(cpu));
#endif
        panic("%s: 1!\n", __func__);
    } else {
        if (req_cpu == WORK_CPU_UNBOUND)
            cpu = raw_smp_processor_id();
        pwq = per_cpu_ptr(wq->cpu_pwqs, cpu);
    }

    /*
     * If @work was previously on a different pool, it might still be
     * running there, in which case the work needs to be queued on that
     * pool to guarantee non-reentrancy.
     */
    last_pool = get_work_pool(work);
    if (last_pool && last_pool != pwq->pool) {
#if 0
        struct worker *worker;

        raw_spin_lock(&last_pool->lock);

        worker = find_worker_executing_work(last_pool, work);

        if (worker && worker->current_pwq->wq == wq) {
            pwq = worker->current_pwq;
        } else {
            /* meh... not running there, queue here */
            raw_spin_unlock(&last_pool->lock);
            raw_spin_lock(&pwq->pool->lock);
        }
#endif
        panic("%s: 2!\n", __func__);
    } else {
        raw_spin_lock(&pwq->pool->lock);
    }

    /*
     * pwq is determined and locked.  For unbound pools, we could have
     * raced with pwq release and it could already be dead.  If its
     * refcnt is zero, repeat pwq selection.  Note that pwqs never die
     * without another pwq replacing it in the numa_pwq_tbl or while
     * work items are executing on it, so the retrying is guaranteed to
     * make forward-progress.
     */
    if (unlikely(!pwq->refcnt)) {
        if (wq->flags & WQ_UNBOUND) {
            raw_spin_unlock(&pwq->pool->lock);
            cpu_relax();
            goto retry;
        }
        /* oops */
        WARN_ONCE(true,
                  "workqueue: per-cpu pwq for %s on cpu%d has 0 refcnt",
                  wq->name, cpu);
    }

    if (WARN_ON(!list_empty(&work->entry)))
        goto out;

    printk("%s: 1\n", __func__);

    pwq->nr_in_flight[pwq->work_color]++;
    work_flags = work_color_to_flags(pwq->work_color);

    if (likely(pwq->nr_active < pwq->max_active)) {
        pwq->nr_active++;
        worklist = &pwq->pool->worklist;
        if (list_empty(worklist))
            pwq->pool->watchdog_ts = jiffies;
    } else {
        work_flags |= WORK_STRUCT_INACTIVE;
        worklist = &pwq->inactive_works;
    }

    printk("%s: 2\n", __func__);
    insert_work(pwq, work, worklist, work_flags);

 out:
    raw_spin_unlock(&pwq->pool->lock);
    rcu_read_unlock();
}

void delayed_work_timer_fn(struct timer_list *t)
{
#if 0
    struct delayed_work *dwork = from_timer(dwork, t, timer);

    /* should have been called from irqsafe timer with irq already off */
    __queue_work(dwork->cpu, dwork->wq, &dwork->work);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(delayed_work_timer_fn);

/**
 * wq_worker_running - a worker is running again
 * @task: task waking up
 *
 * This function is called when a worker returns from schedule()
 */
void wq_worker_running(struct task_struct *task)
{
    struct worker *worker = kthread_data(task);

    if (!worker->sleeping)
        return;

    panic("%s: END!\n", __func__);
}

/**
 * try_to_grab_pending - steal work item from worklist and disable irq
 * @work: work item to steal
 * @is_dwork: @work is a delayed_work
 * @flags: place to store irq state
 *
 * Try to grab PENDING bit of @work.  This function can handle @work in any
 * stable state - idle, on timer or on worklist.
 *
 * Return:
 *
 *  ========    ================================================================
 *  1       if @work was pending and we successfully stole PENDING
 *  0       if @work was idle and we claimed PENDING
 *  -EAGAIN if PENDING couldn't be grabbed at the moment, safe to busy-retry
 *  -ENOENT if someone else is canceling @work, this state may persist
 *      for arbitrarily long
 *  ========    ================================================================
 *
 * Note:
 * On >= 0 return, the caller owns @work's PENDING bit.  To avoid getting
 * interrupted while holding PENDING and @work off queue, irq must be
 * disabled on entry.  This, combined with delayed_work->timer being
 * irqsafe, ensures that we return -EAGAIN for finite short period of time.
 *
 * On successful return, >= 0, irq is disabled and the caller is
 * responsible for releasing it using local_irq_restore(*@flags).
 *
 * This function is safe to call from any context including IRQ handler.
 */
static int try_to_grab_pending(struct work_struct *work, bool is_dwork,
                               unsigned long *flags)
{
    struct worker_pool *pool;
    struct pool_workqueue *pwq;

    local_irq_save(*flags);

    /* try to steal the timer if it exists */
    if (is_dwork) {
        struct delayed_work *dwork = to_delayed_work(work);

        /*
         * dwork->timer is irqsafe.  If del_timer() fails, it's
         * guaranteed that the timer is not queued anywhere and not
         * running on the local CPU.
         */
        if (likely(del_timer(&dwork->timer)))
            return 1;
    }

    /* try to claim PENDING the normal way */
    if (!test_and_set_bit(WORK_STRUCT_PENDING_BIT,
                          work_data_bits(work)))
        return 0;

    panic("%s: END!\n", __func__);
}

static void __queue_delayed_work(int cpu, struct workqueue_struct *wq,
                                 struct delayed_work *dwork,
                                 unsigned long delay)
{
    struct timer_list *timer = &dwork->timer;
    struct work_struct *work = &dwork->work;

    WARN_ON_ONCE(!wq);
    WARN_ON_FUNCTION_MISMATCH(timer->function, delayed_work_timer_fn);
    WARN_ON_ONCE(timer_pending(timer));
    WARN_ON_ONCE(!list_empty(&work->entry));

    /*
     * If @delay is 0, queue @dwork->work immediately.  This is for
     * both optimization and correctness.  The earliest @timer can
     * expire is on the closest next tick and delayed_work users depend
     * on that there's no such delay when @delay is 0.
     */
    if (!delay) {
        __queue_work(cpu, wq, &dwork->work);
        return;
    }

    panic("%s: END!\n", __func__);
}

/**
 * mod_delayed_work_on - modify delay of or queue a delayed work on specific CPU
 * @cpu: CPU number to execute work on
 * @wq: workqueue to use
 * @dwork: work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * If @dwork is idle, equivalent to queue_delayed_work_on(); otherwise,
 * modify @dwork's timer so that it expires after @delay.  If @delay is
 * zero, @work is guaranteed to be scheduled immediately regardless of its
 * current state.
 *
 * Return: %false if @dwork was idle and queued, %true if @dwork was
 * pending and its timer was modified.
 *
 * This function is safe to call from any context including IRQ handler.
 * See try_to_grab_pending() for details.
 */
bool mod_delayed_work_on(int cpu, struct workqueue_struct *wq,
                         struct delayed_work *dwork,
                         unsigned long delay)
{
    unsigned long flags;
    int ret;

    do {
        ret = try_to_grab_pending(&dwork->work, true, &flags);
    } while (unlikely(ret == -EAGAIN));

    if (likely(ret >= 0)) {
        __queue_delayed_work(cpu, wq, dwork, delay);
        local_irq_restore(flags);
    }

    /* -ENOENT from try_to_grab_pending() becomes %true */
    return ret;
}
EXPORT_SYMBOL_GPL(mod_delayed_work_on);

/**
 * free_workqueue_attrs - free a workqueue_attrs
 * @attrs: workqueue_attrs to free
 *
 * Undo alloc_workqueue_attrs().
 */
void free_workqueue_attrs(struct workqueue_attrs *attrs)
{
    if (attrs) {
        free_cpumask_var(attrs->cpumask);
        kfree(attrs);
    }
}

/**
 * alloc_workqueue_attrs - allocate a workqueue_attrs
 *
 * Allocate a new workqueue_attrs, initialize with default settings and
 * return it.
 *
 * Return: The allocated new workqueue_attr on success. %NULL on failure.
 */
struct workqueue_attrs *alloc_workqueue_attrs(void)
{
    struct workqueue_attrs *attrs;

    attrs = kzalloc(sizeof(*attrs), GFP_KERNEL);
    if (!attrs)
        goto fail;
    if (!alloc_cpumask_var(&attrs->cpumask, GFP_KERNEL))
        goto fail;

    cpumask_copy(attrs->cpumask, cpu_possible_mask);
    return attrs;
fail:
    free_workqueue_attrs(attrs);
    return NULL;
}

/**
 * destroy_workqueue - safely terminate a workqueue
 * @wq: target workqueue
 *
 * Safely destroy a workqueue. All work currently pending will be done first.
 */
void destroy_workqueue(struct workqueue_struct *wq)
{
    panic("%s: END!\n", __func__);
}

static int wq_clamp_max_active(int max_active, unsigned int flags,
                               const char *name)
{
    int lim = flags & WQ_UNBOUND ?
        WQ_UNBOUND_MAX_ACTIVE : WQ_MAX_ACTIVE;

    if (max_active < 1 || max_active > lim)
        pr_warn("workqueue: max_active %d requested for %s "
                "is out of range, clamping between %d and %d\n",
                max_active, name, 1, lim);

    return clamp_val(max_active, 1, lim);
}

/**
 * workqueue_sysfs_register - make a workqueue visible in sysfs
 * @wq: the workqueue to register
 *
 * Expose @wq in sysfs under /sys/bus/workqueue/devices.
 * alloc_workqueue*() automatically calls this function if WQ_SYSFS is set
 * which is the preferred method.
 *
 * Workqueue user should use this function directly iff it wants to apply
 * workqueue_attrs before making the workqueue visible in sysfs; otherwise,
 * apply_workqueue_attrs() may race against userland updating the
 * attributes.
 *
 * Return: 0 on success, -errno on failure.
 */
int workqueue_sysfs_register(struct workqueue_struct *wq)
{
    panic("%s: END!\n", __func__);
}

/*
 * Scheduled on system_wq by put_pwq() when an unbound pwq hits zero refcnt
 * and needs to be destroyed.
 */
static void pwq_unbound_release_workfn(struct work_struct *work)
{
    panic("%s: END!\n", __func__);
}

/* initialize newly allocated @pwq which is associated with @wq and @pool */
static void init_pwq(struct pool_workqueue *pwq,
                     struct workqueue_struct *wq,
                     struct worker_pool *pool)
{
    BUG_ON((unsigned long)pwq & WORK_STRUCT_FLAG_MASK);

    memset(pwq, 0, sizeof(*pwq));

    pwq->pool = pool;
    pwq->wq = wq;
    pwq->flush_color = -1;
    pwq->refcnt = 1;
    INIT_LIST_HEAD(&pwq->inactive_works);
    INIT_LIST_HEAD(&pwq->pwqs_node);
    INIT_LIST_HEAD(&pwq->mayday_node);
    INIT_WORK(&pwq->unbound_release_work, pwq_unbound_release_workfn);
}

/**
 * move_linked_works - move linked works to a list
 * @work: start of series of works to be scheduled
 * @head: target list to append @work to
 * @nextp: out parameter for nested worklist walking
 *
 * Schedule linked works starting from @work to @head.  Work series to
 * be scheduled starts at @work and includes any consecutive work with
 * WORK_STRUCT_LINKED set in its predecessor.
 *
 * If @nextp is not NULL, it's updated to point to the next work of
 * the last scheduled work.  This allows move_linked_works() to be
 * nested inside outer list_for_each_entry_safe().
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock).
 */
static void move_linked_works(struct work_struct *work,
                              struct list_head *head,
                              struct work_struct **nextp)
{
    panic("%s: END!\n", __func__);
}

static void pwq_activate_inactive_work(struct work_struct *work)
{
#if 0
    struct pool_workqueue *pwq = get_work_pwq(work);

    if (list_empty(&pwq->pool->worklist))
        pwq->pool->watchdog_ts = jiffies;
    move_linked_works(work, &pwq->pool->worklist, NULL);
    __clear_bit(WORK_STRUCT_INACTIVE_BIT, work_data_bits(work));
    pwq->nr_active++;
#endif
    panic("%s: END!\n", __func__);
}

static void pwq_activate_first_inactive(struct pool_workqueue *pwq)
{
    struct work_struct *work =
        list_first_entry(&pwq->inactive_works, struct work_struct,
                         entry);

    pwq_activate_inactive_work(work);
}

/**
 * pwq_adjust_max_active - update a pwq's max_active to the current setting
 * @pwq: target pool_workqueue
 *
 * If @pwq isn't freezing, set @pwq->max_active to the associated
 * workqueue's saved_max_active and activate inactive work items
 * accordingly.  If @pwq is freezing, clear @pwq->max_active to zero.
 */
static void pwq_adjust_max_active(struct pool_workqueue *pwq)
{
    struct workqueue_struct *wq = pwq->wq;
    bool freezable = wq->flags & WQ_FREEZABLE;
    unsigned long flags;

    /* fast exit for non-freezable wqs */
    if (!freezable && pwq->max_active == wq->saved_max_active)
        return;

    /* this function can be called during early boot w/ irq disabled */
    raw_spin_lock_irqsave(&pwq->pool->lock, flags);

    /*
     * During [un]freezing, the caller is responsible for ensuring that
     * this function is called at least once after @workqueue_freezing
     * is updated and visible.
     */
    if (!freezable || !workqueue_freezing) {
        bool kick = false;

        pwq->max_active = wq->saved_max_active;

        while (!list_empty(&pwq->inactive_works) &&
               pwq->nr_active < pwq->max_active) {
            pwq_activate_first_inactive(pwq);
            kick = true;
        }

        /*
         * Need to kick a worker after thawed or an unbound wq's
         * max_active is bumped. In realtime scenarios, always kicking a
         * worker will cause interference on the isolated cpu cores, so
         * let's kick iff work items were activated.
         */
        if (kick)
            wake_up_worker(pwq->pool);
    } else {
        pwq->max_active = 0;
    }

    raw_spin_unlock_irqrestore(&pwq->pool->lock, flags);
}

/* sync @pwq with the current state of its associated wq and link it */
static void link_pwq(struct pool_workqueue *pwq)
{
    struct workqueue_struct *wq = pwq->wq;

    /* may be called multiple times, ignore if already linked */
    if (!list_empty(&pwq->pwqs_node))
        return;

    /* set the matching work_color */
    pwq->work_color = wq->work_color;

    /* sync max_active to the current setting */
    pwq_adjust_max_active(pwq);

    /* link in @pwq */
    list_add_rcu(&pwq->pwqs_node, &wq->pwqs);
}

static int alloc_and_link_pwqs(struct workqueue_struct *wq)
{
    bool highpri = wq->flags & WQ_HIGHPRI;
    int cpu, ret;

    if (!(wq->flags & WQ_UNBOUND)) {
        wq->cpu_pwqs = alloc_percpu(struct pool_workqueue);
        if (!wq->cpu_pwqs)
            return -ENOMEM;

        for_each_possible_cpu(cpu) {
            struct pool_workqueue *pwq =
                per_cpu_ptr(wq->cpu_pwqs, cpu);
            struct worker_pool *cpu_pools =
                per_cpu(cpu_worker_pools, cpu);

            init_pwq(pwq, wq, &cpu_pools[highpri]);

            mutex_lock(&wq->mutex);
            link_pwq(pwq);
            mutex_unlock(&wq->mutex);
        }
        return 0;
    }

    panic("%s: END!\n", __func__);
}

static struct worker *alloc_worker(int node)
{
    struct worker *worker;

    worker = kzalloc_node(sizeof(*worker), GFP_KERNEL, node);
    if (worker) {
        INIT_LIST_HEAD(&worker->entry);
        INIT_LIST_HEAD(&worker->scheduled);
        INIT_LIST_HEAD(&worker->node);
        /* on creation a worker is in !idle && prep state */
        worker->flags = WORKER_PREP;
    }
    return worker;
}

/**
 * rescuer_thread - the rescuer thread function
 * @__rescuer: self
 *
 * Workqueue rescuer thread function.  There's one rescuer for each
 * workqueue which has WQ_MEM_RECLAIM set.
 *
 * Regular work processing on a pool may block trying to create a new
 * worker which uses GFP_KERNEL allocation which has slight chance of
 * developing into deadlock if some works currently on the same queue
 * need to be processed to satisfy the GFP_KERNEL allocation.  This is
 * the problem rescuer solves.
 *
 * When such condition is possible, the pool summons rescuers of all
 * workqueues which have works queued on the pool and let them process
 * those works so that forward progress can be guaranteed.
 *
 * This should happen rarely.
 *
 * Return: 0
 */
static int rescuer_thread(void *__rescuer)
{
#if 0
    struct worker *rescuer = __rescuer;
    struct workqueue_struct *wq = rescuer->rescue_wq;
    struct list_head *scheduled = &rescuer->scheduled;
    bool should_stop;

    set_user_nice(current, RESCUER_NICE_LEVEL);
#endif

    panic("%s: END!\n", __func__);
}

/*
 * Workqueues which may be used during memory reclaim should have a rescuer
 * to guarantee forward progress.
 */
static int init_rescuer(struct workqueue_struct *wq)
{
    struct worker *rescuer;
    int ret;

    if (!(wq->flags & WQ_MEM_RECLAIM))
        return 0;

    rescuer = alloc_worker(NUMA_NO_NODE);
    if (!rescuer)
        return -ENOMEM;

    rescuer->rescue_wq = wq;
#if 0
    rescuer->task = kthread_create(rescuer_thread, rescuer, "%s",
                                   wq->name);
    if (IS_ERR(rescuer->task)) {
        ret = PTR_ERR(rescuer->task);
        kfree(rescuer);
        return ret;
    }

    wq->rescuer = rescuer;
    kthread_bind_mask(rescuer->task, cpu_possible_mask);
    wake_up_process(rescuer->task);
#endif

    return 0;
}

/**
 * for_each_pwq - iterate through all pool_workqueues of the specified workqueue
 * @pwq: iteration cursor
 * @wq: the target workqueue
 *
 * This must be called either with wq->mutex held or RCU read locked.
 * If the pwq needs to be used beyond the locking in effect, the caller is
 * responsible for guaranteeing that the pwq stays online.
 *
 * The if/else clause exists only for the lockdep assertion and can be
 * ignored.
 */
#define for_each_pwq(pwq, wq)                       \
    list_for_each_entry_rcu((pwq), &(wq)->pwqs, pwqs_node,      \
                 lockdep_is_held(&(wq->mutex)))

__printf(1, 4)
struct workqueue_struct *alloc_workqueue(const char *fmt,
                                         unsigned int flags,
                                         int max_active, ...)
{
    size_t tbl_size = 0;
    va_list args;
    struct workqueue_struct *wq;
    struct pool_workqueue *pwq;

    /*
     * Unbound && max_active == 1 used to imply ordered, which is no
     * longer the case on NUMA machines due to per-node pools.  While
     * alloc_ordered_workqueue() is the right way to create an ordered
     * workqueue, keep the previous behavior to avoid subtle breakages
     * on NUMA.
     */
    if ((flags & WQ_UNBOUND) && max_active == 1)
        flags |= __WQ_ORDERED;

    /* see the comment above the definition of WQ_POWER_EFFICIENT */
    if ((flags & WQ_POWER_EFFICIENT) && wq_power_efficient)
        flags |= WQ_UNBOUND;

    /* allocate wq and format name */
    if (flags & WQ_UNBOUND)
        tbl_size = nr_node_ids * sizeof(wq->numa_pwq_tbl[0]);

    wq = kzalloc(sizeof(*wq) + tbl_size, GFP_KERNEL);
    if (!wq)
        return NULL;

    if (flags & WQ_UNBOUND) {
        wq->unbound_attrs = alloc_workqueue_attrs();
        if (!wq->unbound_attrs)
            goto err_free_wq;
    }

    va_start(args, max_active);
    vsnprintf(wq->name, sizeof(wq->name), fmt, args);
    va_end(args);

    max_active = max_active ?: WQ_DFL_ACTIVE;
    max_active = wq_clamp_max_active(max_active, flags, wq->name);

    /* init wq */
    wq->flags = flags;
    wq->saved_max_active = max_active;
    mutex_init(&wq->mutex);
    atomic_set(&wq->nr_pwqs_to_flush, 0);
    INIT_LIST_HEAD(&wq->pwqs);
    INIT_LIST_HEAD(&wq->flusher_queue);
    INIT_LIST_HEAD(&wq->flusher_overflow);
    INIT_LIST_HEAD(&wq->maydays);

    wq_init_lockdep(wq);
    INIT_LIST_HEAD(&wq->list);

    if (alloc_and_link_pwqs(wq) < 0)
        goto err_unreg_lockdep;

    if (wq_online && init_rescuer(wq) < 0)
        goto err_destroy;

    if ((wq->flags & WQ_SYSFS) && workqueue_sysfs_register(wq))
        goto err_destroy;

    /*
     * wq_pool_mutex protects global freeze state and workqueues list.
     * Grab it, adjust max_active and add the new @wq to workqueues
     * list.
     */
    mutex_lock(&wq_pool_mutex);

    mutex_lock(&wq->mutex);
    for_each_pwq(pwq, wq)
        pwq_adjust_max_active(pwq);
    mutex_unlock(&wq->mutex);

    list_add_tail_rcu(&wq->list, &workqueues);

    mutex_unlock(&wq_pool_mutex);

    return wq;

 err_unreg_lockdep:
    wq_unregister_lockdep(wq);
    wq_free_lockdep(wq);
 err_free_wq:
    free_workqueue_attrs(wq->unbound_attrs);
    kfree(wq);
    return NULL;
 err_destroy:
    destroy_workqueue(wq);
    return NULL;
}
EXPORT_SYMBOL_GPL(alloc_workqueue);

/**
 * cancel_delayed_work - cancel a delayed work
 * @dwork: delayed_work to cancel
 *
 * Kill off a pending delayed_work.
 *
 * Return: %true if @dwork was pending and canceled; %false if it wasn't
 * pending.
 *
 * Note:
 * The work callback function may still be running on return, unless
 * it returns %true and the work doesn't re-arm itself.  Explicitly flush or
 * use cancel_delayed_work_sync() to wait on it.
 *
 * This function is safe to call from any context including IRQ handler.
 */
bool cancel_delayed_work(struct delayed_work *dwork)
{
#if 0
    return __cancel_work(&dwork->work, true);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(cancel_delayed_work);

static void __init wq_numa_init(void)
{
    if (num_possible_nodes() <= 1)
        return;

    panic("%s: END!\n", __func__);
}

/**
 * wq_update_unbound_numa - update NUMA affinity of a wq for CPU hot[un]plug
 * @wq: the target workqueue
 * @cpu: the CPU coming up or going down
 * @online: whether @cpu is coming up or going down
 *
 * This function is to be called from %CPU_DOWN_PREPARE, %CPU_ONLINE and
 * %CPU_DOWN_FAILED.  @cpu is being hot[un]plugged, update NUMA affinity of
 * @wq accordingly.
 *
 * If NUMA affinity can't be adjusted due to memory allocation failure, it
 * falls back to @wq->dfl_pwq which may not be optimal but is always
 * correct.
 *
 * Note that when the last allowed CPU of a NUMA node goes offline for a
 * workqueue with a cpumask spanning multiple nodes, the workers which were
 * already executing the work items for the workqueue will lose their CPU
 * affinity and may execute on any CPU.  This is similar to how per-cpu
 * workqueues behave on CPU_DOWN.  If a workqueue user wants strict
 * affinity, it's the user's responsibility to flush the work item from
 * CPU_DOWN_PREPARE.
 */
static void wq_update_unbound_numa(struct workqueue_struct *wq, int cpu,
                                   bool online)
{
    int node = cpu_to_node(cpu);
    int cpu_off = online ? -1 : cpu;
    struct pool_workqueue *old_pwq = NULL, *pwq;
    struct workqueue_attrs *target_attrs;
    cpumask_t *cpumask;

    if (!wq_numa_enabled || !(wq->flags & WQ_UNBOUND) ||
        wq->unbound_attrs->no_numa)
        return;

    panic("%s: END!\n", __func__);
}

static void set_pf_worker(bool val)
{
    mutex_lock(&wq_pool_attach_mutex);
    if (val)
        current->flags |= PF_WQ_WORKER;
    else
        current->flags &= ~PF_WQ_WORKER;
    mutex_unlock(&wq_pool_attach_mutex);
}

/**
 * worker_detach_from_pool() - detach a worker from its pool
 * @worker: worker which is attached to its pool
 *
 * Undo the attaching which had been done in worker_attach_to_pool().  The
 * caller worker shouldn't access to the pool after detached except it has
 * other reference to the pool.
 */
static void worker_detach_from_pool(struct worker *worker)
{
    panic("%s: END!\n", __func__);
}

/**
 * worker_clr_flags - clear worker flags and adjust nr_running accordingly
 * @worker: self
 * @flags: flags to clear
 *
 * Clear @flags in @worker->flags and adjust nr_running accordingly.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock)
 */
static inline
void worker_clr_flags(struct worker *worker, unsigned int flags)
{
    struct worker_pool *pool = worker->pool;
    unsigned int oflags = worker->flags;

    WARN_ON_ONCE(worker->task != current);

    worker->flags &= ~flags;

    /*
     * If transitioning out of NOT_RUNNING, increment nr_running.  Note
     * that the nested NOT_RUNNING is not a noop.  NOT_RUNNING is mask
     * of multiple flags, not a single flag.
     */
    if ((flags & WORKER_NOT_RUNNING) && (oflags & WORKER_NOT_RUNNING))
        if (!(worker->flags & WORKER_NOT_RUNNING))
            pool->nr_running++;
}

/**
 * worker_leave_idle - leave idle state
 * @worker: worker which is leaving idle state
 *
 * @worker is leaving idle state.  Update stats.
 *
 * LOCKING:
 * raw_spin_lock_irq(pool->lock).
 */
static void worker_leave_idle(struct worker *worker)
{
    struct worker_pool *pool = worker->pool;

    if (WARN_ON_ONCE(!(worker->flags & WORKER_IDLE)))
        return;
    worker_clr_flags(worker, WORKER_IDLE);
    pool->nr_idle--;
    list_del_init(&worker->entry);
}

/**
 * worker_enter_idle - enter idle state
 * @worker: worker which is entering idle state
 *
 * @worker is entering idle state.  Update stats and idle timer if
 * necessary.
 *
 * LOCKING:
 * raw_spin_lock_irq(pool->lock).
 */
static void worker_enter_idle(struct worker *worker)
{
    struct worker_pool *pool = worker->pool;

    if (WARN_ON_ONCE(worker->flags & WORKER_IDLE) ||
        WARN_ON_ONCE(!list_empty(&worker->entry) &&
                     (worker->hentry.next || worker->hentry.pprev)))
        return;

    /* can't use worker_set_flags(), also called from create_worker() */
    worker->flags |= WORKER_IDLE;
    pool->nr_idle++;
    worker->last_active = jiffies;

    /* idle_list is LIFO */
    list_add(&worker->entry, &pool->idle_list);

    if (too_many_workers(pool) && !timer_pending(&pool->idle_timer))
        mod_timer(&pool->idle_timer, jiffies + IDLE_WORKER_TIMEOUT);

    /* Sanity check nr_running. */
    WARN_ON_ONCE(pool->nr_workers == pool->nr_idle && pool->nr_running);
}

/**
 * maybe_create_worker - create a new worker if necessary
 * @pool: pool to create a new worker for
 *
 * Create a new worker for @pool if necessary.  @pool is guaranteed to
 * have at least one idle worker on return from this function.  If
 * creating a new worker takes longer than MAYDAY_INTERVAL, mayday is
 * sent to all rescuers with works scheduled on @pool to resolve
 * possible allocation deadlock.
 *
 * On return, need_to_create_worker() is guaranteed to be %false and
 * may_start_working() %true.
 *
 * LOCKING:
 * raw_spin_lock_irq(pool->lock) which may be released and regrabbed
 * multiple times.  Does GFP_KERNEL allocations.  Called only from
 * manager.
 */
static void maybe_create_worker(struct worker_pool *pool)
__releases(&pool->lock)
__acquires(&pool->lock)
{
 restart:
    raw_spin_unlock_irq(&pool->lock);

    /* if we don't make progress in MAYDAY_INITIAL_TIMEOUT, call for help */
    mod_timer(&pool->mayday_timer, jiffies + MAYDAY_INITIAL_TIMEOUT);

    while (true) {
        if (create_worker(pool) || !need_to_create_worker(pool))
            break;

        schedule_timeout_interruptible(CREATE_COOLDOWN);

        if (!need_to_create_worker(pool))
            break;
    }

    del_timer_sync(&pool->mayday_timer);
    raw_spin_lock_irq(&pool->lock);
    /*
     * This is necessary even after a new worker was just successfully
     * created as @pool->lock was dropped and the new worker might have
     * already become busy.
     */
    if (need_to_create_worker(pool))
        goto restart;
}

/**
 * manage_workers - manage worker pool
 * @worker: self
 *
 * Assume the manager role and manage the worker pool @worker belongs
 * to.  At any given time, there can be only zero or one manager per
 * pool.  The exclusion is handled automatically by this function.
 *
 * The caller can safely start processing works on false return.  On
 * true return, it's guaranteed that need_to_create_worker() is false
 * and may_start_working() is true.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock) which may be released and regrabbed
 * multiple times.  Does GFP_KERNEL allocations.
 *
 * Return:
 * %false if the pool doesn't need management and the caller can safely
 * start processing works, %true if management function was performed and
 * the conditions that the caller verified before calling the function may
 * no longer be true.
 */
static bool manage_workers(struct worker *worker)
{
    struct worker_pool *pool = worker->pool;

    if (pool->flags & POOL_MANAGER_ACTIVE)
        return false;

    pool->flags |= POOL_MANAGER_ACTIVE;
    pool->manager = worker;

    maybe_create_worker(pool);

    pool->manager = NULL;
    pool->flags &= ~POOL_MANAGER_ACTIVE;
    rcuwait_wake_up(&manager_wait);
    return true;
}

/**
 * find_worker_executing_work - find worker which is executing a work
 * @pool: pool of interest
 * @work: work to find worker for
 *
 * Find a worker which is executing @work on @pool by searching
 * @pool->busy_hash which is keyed by the address of @work.  For a worker
 * to match, its current execution should match the address of @work and
 * its work function.  This is to avoid unwanted dependency between
 * unrelated work executions through a work item being recycled while still
 * being executed.
 *
 * This is a bit tricky.  A work item may be freed once its execution
 * starts and nothing prevents the freed area from being recycled for
 * another work item.  If the same work item address ends up being reused
 * before the original execution finishes, workqueue will identify the
 * recycled work item as currently executing and make it wait until the
 * current execution finishes, introducing an unwanted dependency.
 *
 * This function checks the work item address and work function to avoid
 * false positives.  Note that this isn't complete as one may construct a
 * work function which can introduce dependency onto itself through a
 * recycled work item.  Well, if somebody wants to shoot oneself in the
 * foot that badly, there's only so much we can do, and if such deadlock
 * actually occurs, it should be easy to locate the culprit work function.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock).
 *
 * Return:
 * Pointer to worker which is executing @work if found, %NULL
 * otherwise.
 */
static struct worker *
find_worker_executing_work(struct worker_pool *pool,
                           struct work_struct *work)
{
    struct worker *worker;

    hash_for_each_possible(pool->busy_hash, worker, hentry,
                   (unsigned long)work)
        if (worker->current_work == work &&
            worker->current_func == work->func)
            return worker;

    return NULL;
}

/**
 * worker_set_flags - set worker flags and adjust nr_running accordingly
 * @worker: self
 * @flags: flags to set
 *
 * Set @flags in @worker->flags and adjust nr_running accordingly.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock)
 */
static inline
void worker_set_flags(struct worker *worker, unsigned int flags)
{
    struct worker_pool *pool = worker->pool;

    WARN_ON_ONCE(worker->task != current);

    /* If transitioning into NOT_RUNNING, adjust nr_running. */
    if ((flags & WORKER_NOT_RUNNING) &&
        !(worker->flags & WORKER_NOT_RUNNING)) {
        pool->nr_running--;
    }

    worker->flags |= flags;
}

static void set_work_pool_and_clear_pending(struct work_struct *work,
                                            int pool_id)
{
    /*
     * The following wmb is paired with the implied mb in
     * test_and_set_bit(PENDING) and ensures all updates to @work made
     * here are visible to and precede any updates by the next PENDING
     * owner.
     */
    smp_wmb();
    set_work_data(work,
                  (unsigned long)pool_id << WORK_OFFQ_POOL_SHIFT, 0);
    /*
     * The following mb guarantees that previous clear of a PENDING bit
     * will not be reordered with any speculative LOADS or STORES from
     * work->current_func, which is executed afterwards.  This possible
     * reordering can lead to a missed execution on attempt to queue
     * the same @work.  E.g. consider this case:
     *
     *   CPU#0                         CPU#1
     *   ----------------------------  --------------------------------
     *
     * 1  STORE event_indicated
     * 2  queue_work_on() {
     * 3    test_and_set_bit(PENDING)
     * 4 }                             set_..._and_clear_pending() {
     * 5                                 set_work_data() # clear bit
     * 6                                 smp_mb()
     * 7                               work->current_func() {
     * 8                      LOAD event_indicated
     *                 }
     *
     * Without an explicit full barrier speculative LOAD on line 8 can
     * be executed before CPU#0 does STORE on line 1.  If that happens,
     * CPU#0 observes the PENDING bit is still set and new execution of
     * a @work is not queued in a hope, that CPU#1 will eventually
     * finish the queued @work.  Meanwhile CPU#1 does not see
     * event_indicated is set, because speculative LOAD was executed
     * before actual STORE.
     */
    smp_mb();
}

/**
 * put_pwq - put a pool_workqueue reference
 * @pwq: pool_workqueue to put
 *
 * Drop a reference of @pwq.  If its refcnt reaches zero, schedule its
 * destruction.  The caller should be holding the matching pool->lock.
 */
static void put_pwq(struct pool_workqueue *pwq)
{
    if (likely(--pwq->refcnt))
        return;
    if (WARN_ON_ONCE(!(pwq->wq->flags & WQ_UNBOUND)))
        return;
    /*
     * @pwq can't be released under pool->lock, bounce to
     * pwq_unbound_release_workfn().  This never recurses on the same
     * pool->lock as this path is taken only for unbound workqueues and
     * the release work item is scheduled on a per-cpu workqueue.  To
     * avoid lockdep warning, unbound pool->locks are given lockdep
     * subclass of 1 in get_unbound_pool().
     */
    schedule_work(&pwq->unbound_release_work);
}

/**
 * pwq_dec_nr_in_flight - decrement pwq's nr_in_flight
 * @pwq: pwq of interest
 * @work_data: work_data of work which left the queue
 *
 * A work either has completed or is removed from pending queue,
 * decrement nr_in_flight of its pwq and handle workqueue flushing.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock).
 */
static void pwq_dec_nr_in_flight(struct pool_workqueue *pwq,
                                 unsigned long work_data)
{
    int color = get_work_color(work_data);

    if (!(work_data & WORK_STRUCT_INACTIVE)) {
        pwq->nr_active--;
        if (!list_empty(&pwq->inactive_works)) {
            /* one down, submit an inactive one */
            if (pwq->nr_active < pwq->max_active)
                pwq_activate_first_inactive(pwq);
        }
    }

    pwq->nr_in_flight[color]--;

    /* is flush in progress and are we at the flushing tip? */
    if (likely(pwq->flush_color != color))
        goto out_put;

    /* are there still in-flight works? */
    if (pwq->nr_in_flight[color])
        goto out_put;

    /* this pwq is done, clear flush_color */
    pwq->flush_color = -1;

    /*
     * If this was the last pwq, wake up the first flusher.  It
     * will handle the rest.
     */
    if (atomic_dec_and_test(&pwq->wq->nr_pwqs_to_flush))
        complete(&pwq->wq->first_flusher->done);
out_put:
    put_pwq(pwq);
}

/**
 * process_one_work - process single work
 * @worker: self
 * @work: work to process
 *
 * Process @work.  This function contains all the logics necessary to
 * process a single work including synchronization against and
 * interaction with other workers on the same cpu, queueing and
 * flushing.  As long as context requirement is met, any worker can
 * call this function to process a work.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock) which is released and regrabbed.
 */
static void process_one_work(struct worker *worker,
                             struct work_struct *work)
__releases(&pool->lock)
__acquires(&pool->lock)
{
    struct pool_workqueue *pwq = get_work_pwq(work);
    struct worker_pool *pool = worker->pool;
    bool cpu_intensive = pwq->wq->flags & WQ_CPU_INTENSIVE;
    unsigned long work_data;
    struct worker *collision;

    /* ensure we're on the correct CPU */
    WARN_ON_ONCE(!(pool->flags & POOL_DISASSOCIATED) &&
             raw_smp_processor_id() != pool->cpu);

    /*
     * A single work shouldn't be executed concurrently by
     * multiple workers on a single cpu.  Check whether anyone is
     * already processing the work.  If so, defer the work to the
     * currently executing one.
     */
    collision = find_worker_executing_work(pool, work);
    if (unlikely(collision)) {
        move_linked_works(work, &collision->scheduled, NULL);
        return;
    }

    /* claim and dequeue */
    hash_add(pool->busy_hash, &worker->hentry, (unsigned long)work);
    worker->current_work = work;
    worker->current_func = work->func;
    worker->current_pwq = pwq;
    work_data = *work_data_bits(work);
    worker->current_color = get_work_color(work_data);

    /*
     * Record wq name for cmdline and debug reporting, may get
     * overridden through set_worker_desc().
     */
    strscpy(worker->desc, pwq->wq->name, WORKER_DESC_LEN);

    list_del_init(&work->entry);

    /*
     * CPU intensive works don't participate in concurrency management.
     * They're the scheduler's responsibility.  This takes @worker out
     * of concurrency management and the next code block will chain
     * execution of the pending work items.
     */
    if (unlikely(cpu_intensive))
        worker_set_flags(worker, WORKER_CPU_INTENSIVE);

    /*
     * Wake up another worker if necessary.  The condition is always
     * false for normal per-cpu workers since nr_running would always
     * be >= 1 at this point.  This is used to chain execution of the
     * pending work items for WORKER_NOT_RUNNING workers such as the
     * UNBOUND and CPU_INTENSIVE ones.
     */
    if (need_more_worker(pool))
        wake_up_worker(pool);

    /*
     * Record the last pool and clear PENDING which should be the last
     * update to @work.  Also, do this inside @pool->lock so that
     * PENDING and queued state changes happen together while IRQ is
     * disabled.
     */
    set_work_pool_and_clear_pending(work, pool->id);

    raw_spin_unlock_irq(&pool->lock);

    /*
     * Strictly speaking we should mark the invariant state without holding
     * any locks, that is, before these two lock_map_acquire()'s.
     *
     * However, that would result in:
     *
     *   A(W1)
     *   WFC(C)
     *      A(W1)
     *      C(C)
     *
     * Which would create W1->C->W1 dependencies, even though there is no
     * actual deadlock possible. There are two solutions, using a
     * read-recursive acquire on the work(queue) 'locks', but this will then
     * hit the lockdep limitation on recursive locks, or simply discard
     * these locks.
     *
     * AFAICT there is no possible deadlock scenario between the
     * flush_work() and complete() primitives (except for single-threaded
     * workqueues), so hiding them isn't a problem.
     */
    worker->current_func(work);

    if (unlikely(in_atomic())) {
        pr_err("BUG: workqueue leaked lock or atomic: %s/0x%08x/%d\n"
               "     last function: %ps\n",
               current->comm, preempt_count(), task_pid_nr(current),
               worker->current_func);
        //dump_stack();
    }

    /*
     * The following prevents a kworker from hogging CPU on !PREEMPTION
     * kernels, where a requeueing work item waiting for something to
     * happen could deadlock with stop_machine as such work item could
     * indefinitely requeue itself while all other CPUs are trapped in
     * stop_machine. At the same time, report a quiescent RCU state so
     * the same condition doesn't freeze RCU.
     */
    cond_resched();

    raw_spin_lock_irq(&pool->lock);

    /* clear cpu intensive status */
    if (unlikely(cpu_intensive))
        worker_clr_flags(worker, WORKER_CPU_INTENSIVE);

    /* tag the worker for identification in schedule() */
    worker->last_func = worker->current_func;

    /* we're done with it, release */
    hash_del(&worker->hentry);
    worker->current_work = NULL;
    worker->current_func = NULL;
    worker->current_pwq = NULL;
    worker->current_color = INT_MAX;
    pwq_dec_nr_in_flight(pwq, work_data);
}

/**
 * process_scheduled_works - process scheduled works
 * @worker: self
 *
 * Process all scheduled works.  Please note that the scheduled list
 * may change while processing a work, so this function repeatedly
 * fetches a work from the top and executes it.
 *
 * CONTEXT:
 * raw_spin_lock_irq(pool->lock) which may be released and regrabbed
 * multiple times.
 */
static void process_scheduled_works(struct worker *worker)
{
    while (!list_empty(&worker->scheduled)) {
        struct work_struct *work =
            list_first_entry(&worker->scheduled,
                             struct work_struct, entry);
        process_one_work(worker, work);
    }
}

/**
 * worker_thread - the worker thread function
 * @__worker: self
 *
 * The worker thread function.  All workers belong to a worker_pool -
 * either a per-cpu one or dynamic unbound one.  These workers process all
 * work items regardless of their specific target workqueue.  The only
 * exception is work items which belong to workqueues with a rescuer which
 * will be explained in rescuer_thread().
 *
 * Return: 0
 */
static int worker_thread(void *__worker)
{
    struct worker *worker = __worker;
    struct worker_pool *pool = worker->pool;

    /* tell the scheduler that this is a workqueue worker */
    set_pf_worker(true);

 woke_up:
    raw_spin_lock_irq(&pool->lock);

    /* am I supposed to die? */
    if (unlikely(worker->flags & WORKER_DIE)) {
        raw_spin_unlock_irq(&pool->lock);
        WARN_ON_ONCE(!list_empty(&worker->entry));
        set_pf_worker(false);

        set_task_comm(worker->task, "kworker/dying");
        ida_free(&pool->worker_ida, worker->id);
        worker_detach_from_pool(worker);
        kfree(worker);
        return 0;
    }

    worker_leave_idle(worker);

 recheck:
    /* no more worker necessary? */
    if (!need_more_worker(pool))
        goto sleep;

    /* do we need to manage? */
    if (unlikely(!may_start_working(pool)) && manage_workers(worker))
        goto recheck;

    /*
     * ->scheduled list can only be filled while a worker is
     * preparing to process a work or actually processing it.
     * Make sure nobody diddled with it while I was sleeping.
     */
    WARN_ON_ONCE(!list_empty(&worker->scheduled));

    /*
     * Finish PREP stage.  We're guaranteed to have at least one idle
     * worker or that someone else has already assumed the manager
     * role.  This is where @worker starts participating in concurrency
     * management if applicable and concurrency management is restored
     * after being rebound.  See rebind_workers() for details.
     */
    worker_clr_flags(worker, WORKER_PREP | WORKER_REBOUND);

    do {
        struct work_struct *work =
            list_first_entry(&pool->worklist,
                     struct work_struct, entry);

        pool->watchdog_ts = jiffies;

        if (likely(!(*work_data_bits(work) & WORK_STRUCT_LINKED))) {
            /* optimization path, not strictly necessary */
            process_one_work(worker, work);
            if (unlikely(!list_empty(&worker->scheduled)))
                process_scheduled_works(worker);
        } else {
            move_linked_works(work, &worker->scheduled, NULL);
            process_scheduled_works(worker);
        }
    } while (keep_working(pool));

    worker_set_flags(worker, WORKER_PREP);
 sleep:
    /*
     * pool->lock is held and there's no work to process and no need to
     * manage, sleep.  Workers are woken up only while holding
     * pool->lock or from local cpu, so setting the current state
     * before releasing pool->lock is enough to prevent losing any
     * event.
     */
    worker_enter_idle(worker);
    __set_current_state(TASK_IDLE);
    raw_spin_unlock_irq(&pool->lock);
    schedule();
    goto woke_up;
}

/**
 * worker_attach_to_pool() - attach a worker to a pool
 * @worker: worker to be attached
 * @pool: the target pool
 *
 * Attach @worker to @pool.  Once attached, the %WORKER_UNBOUND flag and
 * cpu-binding of @worker are kept coordinated with the pool across
 * cpu-[un]hotplugs.
 */
static void worker_attach_to_pool(struct worker *worker,
                                  struct worker_pool *pool)
{
    mutex_lock(&wq_pool_attach_mutex);

    /*
     * The wq_pool_attach_mutex ensures %POOL_DISASSOCIATED remains
     * stable across this function.  See the comments above the flag
     * definition for details.
     */
    if (pool->flags & POOL_DISASSOCIATED)
        worker->flags |= WORKER_UNBOUND;
    else
        kthread_set_per_cpu(worker->task, pool->cpu);

    if (worker->rescue_wq)
        set_cpus_allowed_ptr(worker->task, pool->attrs->cpumask);

    list_add_tail(&worker->node, &pool->workers);
    worker->pool = pool;

    mutex_unlock(&wq_pool_attach_mutex);
}

/**
 * create_worker - create a new workqueue worker
 * @pool: pool the new worker will belong to
 *
 * Create and start a new worker which is attached to @pool.
 *
 * CONTEXT:
 * Might sleep.  Does GFP_KERNEL allocations.
 *
 * Return:
 * Pointer to the newly created worker.
 */
static struct worker *create_worker(struct worker_pool *pool)
{
    struct worker *worker;
    int id;
    char id_buf[16];

    /* ID is needed to determine kthread name */
    id = ida_alloc(&pool->worker_ida, GFP_KERNEL);
    if (id < 0)
        return NULL;

    worker = alloc_worker(pool->node);
    if (!worker)
        goto fail;

    worker->id = id;

    if (pool->cpu >= 0)
        snprintf(id_buf, sizeof(id_buf), "%d:%d%s", pool->cpu, id,
                 pool->attrs->nice < 0  ? "H" : "");
    else
        snprintf(id_buf, sizeof(id_buf), "u%d:%d", pool->id, id);

    worker->task = kthread_create_on_node(worker_thread, worker,
                                          pool->node,
                                          "kworker/%s", id_buf);
    if (IS_ERR(worker->task))
        goto fail;

    set_user_nice(worker->task, pool->attrs->nice);
    kthread_bind_mask(worker->task, pool->attrs->cpumask);

    /* successful, attach the worker to the pool */
    worker_attach_to_pool(worker, pool);

    /* start the newly created worker */
    raw_spin_lock_irq(&pool->lock);
    worker->pool->nr_workers++;
    worker_enter_idle(worker);
    wake_up_process(worker->task);
    raw_spin_unlock_irq(&pool->lock);

    return worker;

 fail:
    ida_free(&pool->worker_ida, id);
    kfree(worker);
    return NULL;
}

static void wq_watchdog_init(void)
{
#if 0
    timer_setup(&wq_watchdog_timer, wq_watchdog_timer_fn,
                TIMER_DEFERRABLE);
    wq_watchdog_set_thresh(wq_watchdog_thresh);
#endif
    panic("%s: END!\n", __func__);
}

static void idle_worker_timeout(struct timer_list *t)
{
    panic("%s: END!\n", __func__);
}

static void pool_mayday_timeout(struct timer_list *t)
{
    panic("%s: END!\n", __func__);
}

/**
 * init_worker_pool - initialize a newly zalloc'd worker_pool
 * @pool: worker_pool to initialize
 *
 * Initialize a newly zalloc'd @pool.  It also allocates @pool->attrs.
 *
 * Return: 0 on success, -errno on failure.  Even on failure, all fields
 * inside @pool proper are initialized and put_unbound_pool() can be called
 * on @pool safely to release it.
 */
static int init_worker_pool(struct worker_pool *pool)
{
    raw_spin_lock_init(&pool->lock);
    pool->id = -1;
    pool->cpu = -1;
    pool->node = NUMA_NO_NODE;
    pool->flags |= POOL_DISASSOCIATED;
    pool->watchdog_ts = jiffies;
    INIT_LIST_HEAD(&pool->worklist);
    INIT_LIST_HEAD(&pool->idle_list);
    hash_init(pool->busy_hash);

    timer_setup(&pool->idle_timer, idle_worker_timeout,
                TIMER_DEFERRABLE);

    timer_setup(&pool->mayday_timer, pool_mayday_timeout, 0);

    INIT_LIST_HEAD(&pool->workers);

    ida_init(&pool->worker_ida);
    INIT_HLIST_NODE(&pool->hash_node);
    pool->refcnt = 1;

    /* shouldn't fail above this point */
    pool->attrs = alloc_workqueue_attrs();
    if (!pool->attrs)
        return -ENOMEM;
    return 0;
}

/**
 * worker_pool_assign_id - allocate ID and assign it to @pool
 * @pool: the pool pointer of interest
 *
 * Returns 0 if ID in [0, WORK_OFFQ_POOL_NONE) is allocated and assigned
 * successfully, -errno on failure.
 */
static int worker_pool_assign_id(struct worker_pool *pool)
{
    int ret;

    ret = idr_alloc(&worker_pool_idr, pool, 0, WORK_OFFQ_POOL_NONE,
                    GFP_KERNEL);
    if (ret >= 0) {
        pool->id = ret;
        return 0;
    }
    return ret;
}

/**
 * workqueue_init_early - early init for workqueue subsystem
 *
 * This is the first half of two-staged workqueue subsystem initialization
 * and invoked as soon as the bare basics - memory allocation, cpumasks and
 * idr are up.  It sets up all the data structures and system workqueues
 * and allows early boot code to create workqueues and queue/cancel work
 * items.  Actual work item execution starts only after kthreads can be
 * created and scheduled right before early initcalls.
 */
void __init workqueue_init_early(void)
{
    int std_nice[NR_STD_WORKER_POOLS] = { 0, HIGHPRI_NICE_LEVEL };
    int i, cpu;

    BUILD_BUG_ON(__alignof__(struct pool_workqueue) < __alignof__(long long));

    BUG_ON(!alloc_cpumask_var(&wq_unbound_cpumask, GFP_KERNEL));
    cpumask_copy(wq_unbound_cpumask, housekeeping_cpumask(HK_TYPE_WQ));
    cpumask_and(wq_unbound_cpumask, wq_unbound_cpumask,
                housekeeping_cpumask(HK_TYPE_DOMAIN));

    pwq_cache = KMEM_CACHE(pool_workqueue, SLAB_PANIC);
    /* initialize CPU pools */
    for_each_possible_cpu(cpu) {
        struct worker_pool *pool;

        i = 0;
        for_each_cpu_worker_pool(pool, cpu) {
            BUG_ON(init_worker_pool(pool));
            pool->cpu = cpu;
            cpumask_copy(pool->attrs->cpumask, cpumask_of(cpu));
            pool->attrs->nice = std_nice[i++];
            pool->node = cpu_to_node(cpu);

            /* alloc pool ID */
            mutex_lock(&wq_pool_mutex);
            BUG_ON(worker_pool_assign_id(pool));
            mutex_unlock(&wq_pool_mutex);
        }
    }

    /* create default unbound and ordered wq attrs */
    for (i = 0; i < NR_STD_WORKER_POOLS; i++) {
        struct workqueue_attrs *attrs;

        BUG_ON(!(attrs = alloc_workqueue_attrs()));
        attrs->nice = std_nice[i];
        unbound_std_wq_attrs[i] = attrs;

        /*
         * An ordered wq should have only one pwq as ordering is
         * guaranteed by max_active which is enforced by pwqs.
         * Turn off NUMA so that dfl_pwq is used for all nodes.
         */
        BUG_ON(!(attrs = alloc_workqueue_attrs()));
        attrs->nice = std_nice[i];
        attrs->no_numa = true;
        ordered_wq_attrs[i] = attrs;
    }

    system_wq = alloc_workqueue("events", 0, 0);
#if 0
    system_highpri_wq = alloc_workqueue("events_highpri", WQ_HIGHPRI, 0);
    system_long_wq = alloc_workqueue("events_long", 0, 0);
    system_unbound_wq = alloc_workqueue("events_unbound", WQ_UNBOUND,
                        WQ_UNBOUND_MAX_ACTIVE);
    system_freezable_wq = alloc_workqueue("events_freezable",
                          WQ_FREEZABLE, 0);
    system_power_efficient_wq = alloc_workqueue("events_power_efficient",
                          WQ_POWER_EFFICIENT, 0);
    system_freezable_power_efficient_wq = alloc_workqueue("events_freezable_power_efficient",
                          WQ_FREEZABLE | WQ_POWER_EFFICIENT,
                          0);
    BUG_ON(!system_wq || !system_highpri_wq || !system_long_wq ||
           !system_unbound_wq || !system_freezable_wq ||
           !system_power_efficient_wq ||
           !system_freezable_power_efficient_wq);
#endif
}

/**
 * wq_worker_sleeping - a worker is going to sleep
 * @task: task going to sleep
 *
 * This function is called from schedule() when a busy worker is
 * going to sleep.
 */
void wq_worker_sleeping(struct task_struct *task)
{
    struct worker *worker = kthread_data(task);
    struct worker_pool *pool;

    /*
     * Rescuers, which may not have all the fields set up like normal
     * workers, also reach here, let's not access anything before
     * checking NOT_RUNNING.
     */
    if (worker->flags & WORKER_NOT_RUNNING)
        return;

    panic("%s: END!\n", __func__);
}

/**
 * queue_work_on - queue work on specific cpu
 * @cpu: CPU number to execute work on
 * @wq: workqueue to use
 * @work: work to queue
 *
 * We queue the work to a specific CPU, the caller must ensure it
 * can't go away.  Callers that fail to ensure that the specified
 * CPU cannot go away will execute on a randomly chosen CPU.
 *
 * Return: %false if @work was already on a queue, %true otherwise.
 */
bool queue_work_on(int cpu, struct workqueue_struct *wq,
                   struct work_struct *work)
{
    bool ret = false;
    unsigned long flags;

    local_irq_save(flags);

    if (!test_and_set_bit(WORK_STRUCT_PENDING_BIT,
                          work_data_bits(work))) {
        __queue_work(cpu, wq, work);
        ret = true;
    }

    local_irq_restore(flags);
    return ret;
}
EXPORT_SYMBOL(queue_work_on);

/**
 * workqueue_init - bring workqueue subsystem fully online
 *
 * This is the latter half of two-staged workqueue subsystem initialization
 * and invoked as soon as kthreads can be created and scheduled.
 * Workqueues have been created and work items queued on them, but there
 * are no kworkers executing the work items yet.  Populate the worker pools
 * with the initial workers and enable future kworker creations.
 */
void __init workqueue_init(void)
{
    struct workqueue_struct *wq;
    struct worker_pool *pool;
    int cpu, bkt;

    /*
     * It'd be simpler to initialize NUMA in workqueue_init_early() but
     * CPU to node mapping may not be available that early on some
     * archs such as power and arm64.  As per-cpu pools created
     * previously could be missing node hint and unbound pools NUMA
     * affinity, fix them up.
     *
     * Also, while iterating workqueues, create rescuers if requested.
     */
    wq_numa_init();

    mutex_lock(&wq_pool_mutex);

    for_each_possible_cpu(cpu) {
        for_each_cpu_worker_pool(pool, cpu) {
            pool->node = cpu_to_node(cpu);
        }
    }

    list_for_each_entry(wq, &workqueues, list) {
        wq_update_unbound_numa(wq, smp_processor_id(), true);
        WARN(init_rescuer(wq),
             "workqueue: failed to create early rescuer for %s",
             wq->name);
    }

    mutex_unlock(&wq_pool_mutex);

    /* create the initial workers */
    for_each_online_cpu(cpu) {
        for_each_cpu_worker_pool(pool, cpu) {
            pool->flags &= ~POOL_DISASSOCIATED;
            BUG_ON(!create_worker(pool));
        }
    }

    hash_for_each(unbound_pool_hash, bkt, pool, hash_node)
        BUG_ON(!create_worker(pool));

    wq_online = true;
#if 0
    wq_watchdog_init();
#endif
}
