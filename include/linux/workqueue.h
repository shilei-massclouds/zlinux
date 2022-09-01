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

#endif /* _LINUX_WORKQUEUE_H */
