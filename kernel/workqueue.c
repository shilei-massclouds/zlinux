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

#include "workqueue_internal.h"

/* see the comment above the definition of WQ_POWER_EFFICIENT */
static bool wq_power_efficient = false;

static bool wq_online;          /* can kworkers be created yet? */

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

/* PL: hash of all unbound pools keyed by pool->attrs */
static DEFINE_HASHTABLE(unbound_pool_hash, UNBOUND_POOL_HASH_ORDER);

/* the per-cpu worker pools */
static DEFINE_PER_CPU_SHARED_ALIGNED(struct worker_pool [NR_STD_WORKER_POOLS], cpu_worker_pools);

#define for_each_cpu_worker_pool(pool, cpu)             \
    for ((pool) = &per_cpu(cpu_worker_pools, cpu)[0];       \
         (pool) < &per_cpu(cpu_worker_pools, cpu)[NR_STD_WORKER_POOLS]; \
         (pool)++)

static void wq_init_lockdep(struct workqueue_struct *wq)
{
}

static void wq_unregister_lockdep(struct workqueue_struct *wq)
{
}

static void wq_free_lockdep(struct workqueue_struct *wq)
{
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

    panic("%s: END!\n", __func__);
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
#if 0
        __queue_work(cpu, wq, &dwork->work);
#endif
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
    panic("%s: END!\n", __func__);
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
    panic("%s: END!\n", __func__);
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
#if 0
    for_each_online_cpu(cpu) {
        for_each_cpu_worker_pool(pool, cpu) {
            pool->flags &= ~POOL_DISASSOCIATED;
            BUG_ON(!create_worker(pool));
        }
    }
#endif

    hash_for_each(unbound_pool_hash, bkt, pool, hash_node)
        BUG_ON(!create_worker(pool));

    wq_online = true;
#if 0
    wq_watchdog_init();
#endif
}
