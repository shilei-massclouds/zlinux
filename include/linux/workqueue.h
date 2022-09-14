/* SPDX-License-Identifier: GPL-2.0 */
/*
 * workqueue.h --- work queue handling for Linux.
 */

#ifndef _LINUX_WORKQUEUE_H
#define _LINUX_WORKQUEUE_H

#include <linux/timer.h>
#include <linux/linkage.h>
#include <linux/bitops.h>
#include <linux/lockdep.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/rcupdate.h>

struct workqueue_struct;

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);
void delayed_work_timer_fn(struct timer_list *t);

enum {
    WORK_STRUCT_PENDING_BIT = 0,    /* work item is pending execution */
    WORK_STRUCT_INACTIVE_BIT= 1,    /* work item is inactive */
    WORK_STRUCT_PWQ_BIT = 2,    /* data points to pwq */
    WORK_STRUCT_LINKED_BIT  = 3,    /* next work is linked to this one */
    WORK_STRUCT_COLOR_SHIFT = 4,    /* color for workqueue flushing */
    WORK_STRUCT_COLOR_BITS  = 4,

    WORK_STRUCT_PENDING = 1 << WORK_STRUCT_PENDING_BIT,
    WORK_STRUCT_INACTIVE    = 1 << WORK_STRUCT_INACTIVE_BIT,
    WORK_STRUCT_PWQ     = 1 << WORK_STRUCT_PWQ_BIT,
    WORK_STRUCT_LINKED  = 1 << WORK_STRUCT_LINKED_BIT,
    WORK_STRUCT_STATIC  = 0,

    WORK_NR_COLORS      = (1 << WORK_STRUCT_COLOR_BITS),

    /* not bound to any CPU, prefer the local CPU */
    WORK_CPU_UNBOUND    = NR_CPUS,

    /*
     * Reserve 8 bits off of pwq pointer w/ debugobjects turned off.
     * This makes pwqs aligned to 256 bytes and allows 16 workqueue
     * flush colors.
     */
    WORK_STRUCT_FLAG_BITS   = WORK_STRUCT_COLOR_SHIFT +
                  WORK_STRUCT_COLOR_BITS,

    /* data contains off-queue information when !WORK_STRUCT_PWQ */
    WORK_OFFQ_FLAG_BASE = WORK_STRUCT_COLOR_SHIFT,

    __WORK_OFFQ_CANCELING   = WORK_OFFQ_FLAG_BASE,
    WORK_OFFQ_CANCELING = (1 << __WORK_OFFQ_CANCELING),

    /*
     * When a work item is off queue, its high bits point to the last
     * pool it was on.  Cap at 31 bits and use the highest number to
     * indicate that no pool is associated.
     */
    WORK_OFFQ_FLAG_BITS = 1,
    WORK_OFFQ_POOL_SHIFT    = WORK_OFFQ_FLAG_BASE + WORK_OFFQ_FLAG_BITS,
    WORK_OFFQ_LEFT      = BITS_PER_LONG - WORK_OFFQ_POOL_SHIFT,
    WORK_OFFQ_POOL_BITS = WORK_OFFQ_LEFT <= 31 ? WORK_OFFQ_LEFT : 31,
    WORK_OFFQ_POOL_NONE = (1LU << WORK_OFFQ_POOL_BITS) - 1,

    /* convenience constants */
    WORK_STRUCT_FLAG_MASK   = (1UL << WORK_STRUCT_FLAG_BITS) - 1,
    WORK_STRUCT_WQ_DATA_MASK = ~WORK_STRUCT_FLAG_MASK,
    WORK_STRUCT_NO_POOL = (unsigned long)WORK_OFFQ_POOL_NONE << WORK_OFFQ_POOL_SHIFT,

    /* bit mask for work_busy() return values */
    WORK_BUSY_PENDING   = 1 << 0,
    WORK_BUSY_RUNNING   = 1 << 1,

    /* maximum string length for set_worker_desc() */
    WORKER_DESC_LEN     = 24,
};

/*
 * Workqueue flags and constants.  For details, please refer to
 * Documentation/core-api/workqueue.rst.
 */
enum {
    WQ_UNBOUND      = 1 << 1, /* not bound to any cpu */
    WQ_FREEZABLE        = 1 << 2, /* freeze during suspend */
    WQ_MEM_RECLAIM      = 1 << 3, /* may be used for memory reclaim */
    WQ_HIGHPRI      = 1 << 4, /* high priority */
    WQ_CPU_INTENSIVE    = 1 << 5, /* cpu intensive workqueue */
    WQ_SYSFS        = 1 << 6, /* visible in sysfs, see workqueue_sysfs_register() */

    /*
     * Per-cpu workqueues are generally preferred because they tend to
     * show better performance thanks to cache locality.  Per-cpu
     * workqueues exclude the scheduler from choosing the CPU to
     * execute the worker threads, which has an unfortunate side effect
     * of increasing power consumption.
     *
     * The scheduler considers a CPU idle if it doesn't have any task
     * to execute and tries to keep idle cores idle to conserve power;
     * however, for example, a per-cpu work item scheduled from an
     * interrupt handler on an idle CPU will force the scheduler to
     * execute the work item on that CPU breaking the idleness, which in
     * turn may lead to more scheduling choices which are sub-optimal
     * in terms of power consumption.
     *
     * Workqueues marked with WQ_POWER_EFFICIENT are per-cpu by default
     * but become unbound if workqueue.power_efficient kernel param is
     * specified.  Per-cpu workqueues which are identified to
     * contribute significantly to power-consumption are identified and
     * marked with this flag and enabling the power_efficient mode
     * leads to noticeable power saving at the cost of small
     * performance disadvantage.
     *
     * http://thread.gmane.org/gmane.linux.kernel/1480396
     */
    WQ_POWER_EFFICIENT  = 1 << 7,

    __WQ_DRAINING       = 1 << 16, /* internal: workqueue is draining */
    __WQ_ORDERED        = 1 << 17, /* internal: workqueue is ordered */
    __WQ_LEGACY     = 1 << 18, /* internal: create*_workqueue() */
    __WQ_ORDERED_EXPLICIT   = 1 << 19, /* internal: alloc_ordered_workqueue() */

    WQ_MAX_ACTIVE       = 512,    /* I like 512, better ideas? */
    WQ_MAX_UNBOUND_PER_CPU  = 4,      /* 4 * #cpus for unbound wq */
    WQ_DFL_ACTIVE       = WQ_MAX_ACTIVE / 2,
};

/* unbound wq's aren't per-cpu, scale max_active according to #cpus */
#define WQ_UNBOUND_MAX_ACTIVE   \
    max_t(int, WQ_MAX_ACTIVE,   \
          num_possible_cpus() * WQ_MAX_UNBOUND_PER_CPU)

struct work_struct {
    atomic_long_t data;
    struct list_head entry;
    work_func_t func;
};

struct delayed_work {
    struct work_struct work;
    struct timer_list timer;

    /* target workqueue and CPU ->timer uses to queue ->work */
    struct workqueue_struct *wq;
    int cpu;
};

/**
 * struct workqueue_attrs - A struct for workqueue attributes.
 *
 * This can be used to change attributes of an unbound workqueue.
 */
struct workqueue_attrs {
    /**
     * @nice: nice level
     */
    int nice;

    /**
     * @cpumask: allowed CPUs
     */
    cpumask_var_t cpumask;

    /**
     * @no_numa: disable NUMA affinity
     *
     * Unlike other fields, ``no_numa`` isn't a property of a worker_pool. It
     * only modifies how :c:func:`apply_workqueue_attrs` select pools and thus
     * doesn't participate in pool hash calculations or equality comparisons.
     */
    bool no_numa;
};

struct rcu_work {
    struct work_struct work;
    struct rcu_head rcu;

    /* target workqueue ->rcu uses to queue ->work */
    struct workqueue_struct *wq;
};

/*
 * System-wide workqueues which are always present.
 *
 * system_wq is the one used by schedule[_delayed]_work[_on]().
 * Multi-CPU multi-threaded.  There are users which expect relatively
 * short queue flush time.  Don't queue works which can run for too
 * long.
 *
 * system_highpri_wq is similar to system_wq but for work items which
 * require WQ_HIGHPRI.
 *
 * system_long_wq is similar to system_wq but may host long running
 * works.  Queue flushing might take relatively long.
 *
 * system_unbound_wq is unbound workqueue.  Workers are not bound to
 * any specific CPU, not concurrency managed, and all queued works are
 * executed immediately as long as max_active limit is not reached and
 * resources are available.
 *
 * system_freezable_wq is equivalent to system_wq except that it's
 * freezable.
 *
 * *_power_efficient_wq are inclined towards saving power and converted
 * into WQ_UNBOUND variants if 'wq_power_efficient' is enabled; otherwise,
 * they are same as their non-power-efficient counterparts - e.g.
 * system_power_efficient_wq is identical to system_wq if
 * 'wq_power_efficient' is disabled.  See WQ_POWER_EFFICIENT for more info.
 */
extern struct workqueue_struct *system_wq;
extern struct workqueue_struct *system_highpri_wq;
extern struct workqueue_struct *system_long_wq;
extern struct workqueue_struct *system_unbound_wq;
extern struct workqueue_struct *system_freezable_wq;
extern struct workqueue_struct *system_power_efficient_wq;
extern struct workqueue_struct *system_freezable_power_efficient_wq;

#define WORK_DATA_INIT()    ATOMIC_LONG_INIT((unsigned long)WORK_STRUCT_NO_POOL)
#define WORK_DATA_STATIC_INIT() \
    ATOMIC_LONG_INIT((unsigned long)(WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC))

#define __WORK_INITIALIZER(n, f) {                  \
    .data = WORK_DATA_STATIC_INIT(),                \
    .entry  = { &(n).entry, &(n).entry },               \
    .func = (f),                            \
    }

#define __DELAYED_WORK_INITIALIZER(n, f, tflags) {          \
    .work = __WORK_INITIALIZER((n).work, (f)),          \
    .timer = __TIMER_INITIALIZER(delayed_work_timer_fn,\
                     (tflags) | TIMER_IRQSAFE),     \
    }

extern bool mod_delayed_work_on(int cpu, struct workqueue_struct *wq,
                                struct delayed_work *dwork,
                                unsigned long delay);

/**
 * alloc_workqueue - allocate a workqueue
 * @fmt: printf format for the name of the workqueue
 * @flags: WQ_* flags
 * @max_active: max in-flight work items, 0 for default
 * remaining args: args for @fmt
 *
 * Allocate a workqueue with the specified parameters.  For detailed
 * information on WQ_* flags, please refer to
 * Documentation/core-api/workqueue.rst.
 *
 * RETURNS:
 * Pointer to the allocated workqueue on success, %NULL on failure.
 */
__printf(1, 4) struct workqueue_struct *
alloc_workqueue(const char *fmt, unsigned int flags, int max_active,
                ...);

extern bool cancel_delayed_work(struct delayed_work *dwork);

static inline
void __init_work(struct work_struct *work, int onstack) { }
static inline
void destroy_work_on_stack(struct work_struct *work) { }
static inline
void destroy_delayed_work_on_stack(struct delayed_work *work) { }
static inline
unsigned int work_static(struct work_struct *work) { return 0; }

#define __INIT_WORK(_work, _func, _onstack)             \
    do {                                \
        __init_work((_work), _onstack);             \
        (_work)->data = (atomic_long_t) WORK_DATA_INIT();   \
        INIT_LIST_HEAD(&(_work)->entry);            \
        (_work)->func = (_func);                \
    } while (0)

#define INIT_WORK(_work, _func)                     \
    __INIT_WORK((_work), (_func), 0)

#define __INIT_DELAYED_WORK(_work, _func, _tflags)  \
    do {                                            \
        INIT_WORK(&(_work)->work, (_func));         \
        __init_timer(&(_work)->timer,               \
                 delayed_work_timer_fn,             \
                 (_tflags) | TIMER_IRQSAFE);        \
    } while (0)

#define INIT_DELAYED_WORK(_work, _func) \
    __INIT_DELAYED_WORK(_work, _func, 0)

void __init workqueue_init_early(void);
void __init workqueue_init(void);

int workqueue_sysfs_register(struct workqueue_struct *wq);

static inline
struct delayed_work *to_delayed_work(struct work_struct *work)
{
    return container_of(work, struct delayed_work, work);
}

/*
 * The first word is the work queue pointer and the flags rolled into
 * one
 */
#define work_data_bits(work) ((unsigned long *)(&(work)->data))

/**
 * work_pending - Find out whether a work item is currently pending
 * @work: The work item in question
 */
#define work_pending(work) \
    test_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))

extern bool queue_work_on(int cpu, struct workqueue_struct *wq,
                          struct work_struct *work);

/**
 * queue_work - queue work on a workqueue
 * @wq: workqueue to use
 * @work: work to queue
 *
 * Returns %false if @work was already on a queue, %true otherwise.
 *
 * We queue the work to the CPU on which it was submitted, but if the CPU dies
 * it can be processed by another CPU.
 *
 * Memory-ordering properties:  If it returns %true, guarantees that all stores
 * preceding the call to queue_work() in the program order will be visible from
 * the CPU which will execute @work by the time such work executes, e.g.,
 *
 * { x is initially 0 }
 *
 *   CPU0               CPU1
 *
 *   WRITE_ONCE(x, 1);          [ @work is being executed ]
 *   r0 = queue_work(wq, work);       r1 = READ_ONCE(x);
 *
 * Forbids: r0 == true && r1 == 0
 */
static inline
bool queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
    return queue_work_on(WORK_CPU_UNBOUND, wq, work);
}

/**
 * schedule_work - put work task in global workqueue
 * @work: job to be done
 *
 * Returns %false if @work was already on the kernel-global workqueue and
 * %true otherwise.
 *
 * This puts a job in the kernel-global workqueue if it was not already
 * queued and leaves it in the same position on the kernel-global
 * workqueue otherwise.
 *
 * Shares the same memory-ordering properties of queue_work(), cf. the
 * DocBook header of queue_work().
 */
static inline bool schedule_work(struct work_struct *work)
{
    return queue_work(system_wq, work);
}

#endif /* _LINUX_WORKQUEUE_H */
