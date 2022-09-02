// SPDX-License-Identifier: GPL-2.0
/*
 *  hrtimers - High-resolution kernel timers
 *
 *   Copyright(C) 2005, Thomas Gleixner <tglx@linutronix.de>
 *   Copyright(C) 2005, Red Hat, Inc., Ingo Molnar
 *
 *  data type definitions, declarations, prototypes
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 */
#ifndef _LINUX_HRTIMER_H
#define _LINUX_HRTIMER_H

//#include <linux/hrtimer_defs.h>
#include <linux/rbtree.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/percpu.h>
#include <linux/seqlock.h>
#include <linux/timer.h>
#include <linux/timerqueue.h>

/*
 * Values to track state of the timer
 *
 * Possible states:
 *
 * 0x00     inactive
 * 0x01     enqueued into rbtree
 *
 * The callback state is not part of the timer->state because clearing it would
 * mean touching the timer after the callback, this makes it impossible to free
 * the timer from the callback function.
 *
 * Therefore we track the callback state in:
 *
 *  timer->base->cpu_base->running == timer
 *
 * On SMP it is possible to have a "callback function running and enqueued"
 * status. It happens for example when a posix timer expired and the callback
 * queued a signal. Between dropping the lock which protects the posix timer
 * and reacquiring the base lock of the hrtimer, another CPU can deliver the
 * signal and rearm the timer.
 *
 * All state transitions are protected by cpu_base->lock.
 */
#define HRTIMER_STATE_INACTIVE  0x00
#define HRTIMER_STATE_ENQUEUED  0x01

struct hrtimer_clock_base;
struct hrtimer_cpu_base;

/*
 * Mode arguments of xxx_hrtimer functions:
 *
 * HRTIMER_MODE_ABS     - Time value is absolute
 * HRTIMER_MODE_REL     - Time value is relative to now
 * HRTIMER_MODE_PINNED      - Timer is bound to CPU (is only considered
 *                when starting the timer)
 * HRTIMER_MODE_SOFT        - Timer callback function will be executed in
 *                soft irq context
 * HRTIMER_MODE_HARD        - Timer callback function will be executed in
 *                hard irq context even on PREEMPT_RT.
 */
enum hrtimer_mode {
    HRTIMER_MODE_ABS    = 0x00,
    HRTIMER_MODE_REL    = 0x01,
    HRTIMER_MODE_PINNED = 0x02,
    HRTIMER_MODE_SOFT   = 0x04,
    HRTIMER_MODE_HARD   = 0x08,

    HRTIMER_MODE_ABS_PINNED = HRTIMER_MODE_ABS | HRTIMER_MODE_PINNED,
    HRTIMER_MODE_REL_PINNED = HRTIMER_MODE_REL | HRTIMER_MODE_PINNED,

    HRTIMER_MODE_ABS_SOFT   = HRTIMER_MODE_ABS | HRTIMER_MODE_SOFT,
    HRTIMER_MODE_REL_SOFT   = HRTIMER_MODE_REL | HRTIMER_MODE_SOFT,

    HRTIMER_MODE_ABS_PINNED_SOFT = HRTIMER_MODE_ABS_PINNED | HRTIMER_MODE_SOFT,
    HRTIMER_MODE_REL_PINNED_SOFT = HRTIMER_MODE_REL_PINNED | HRTIMER_MODE_SOFT,

    HRTIMER_MODE_ABS_HARD   = HRTIMER_MODE_ABS | HRTIMER_MODE_HARD,
    HRTIMER_MODE_REL_HARD   = HRTIMER_MODE_REL | HRTIMER_MODE_HARD,

    HRTIMER_MODE_ABS_PINNED_HARD = HRTIMER_MODE_ABS_PINNED | HRTIMER_MODE_HARD,
    HRTIMER_MODE_REL_PINNED_HARD = HRTIMER_MODE_REL_PINNED | HRTIMER_MODE_HARD,
};

/**
 * struct hrtimer - the basic hrtimer structure
 * @node:   timerqueue node, which also manages node.expires,
 *      the absolute expiry time in the hrtimers internal
 *      representation. The time is related to the clock on
 *      which the timer is based. Is setup by adding
 *      slack to the _softexpires value. For non range timers
 *      identical to _softexpires.
 * @_softexpires: the absolute earliest expiry time of the hrtimer.
 *      The time which was given as expiry time when the timer
 *      was armed.
 * @function:   timer expiry callback function
 * @base:   pointer to the timer base (per cpu and per clock)
 * @state:  state information (See bit values above)
 * @is_rel: Set if the timer was armed relative
 * @is_soft:    Set if hrtimer will be expired in soft interrupt context.
 * @is_hard:    Set if hrtimer will be expired in hard interrupt context
 *      even on RT.
 *
 * The hrtimer structure must be initialized by hrtimer_init()
 */
struct hrtimer {
    struct timerqueue_node      node;
    ktime_t                     _softexpires;
    enum hrtimer_restart        (*function)(struct hrtimer *);
    struct hrtimer_clock_base   *base;
    u8              state;
    u8              is_rel;
    u8              is_soft;
    u8              is_hard;
};

enum  hrtimer_base_type {
    HRTIMER_BASE_MONOTONIC,
    HRTIMER_BASE_REALTIME,
    HRTIMER_BASE_BOOTTIME,
    HRTIMER_BASE_TAI,
    HRTIMER_BASE_MONOTONIC_SOFT,
    HRTIMER_BASE_REALTIME_SOFT,
    HRTIMER_BASE_BOOTTIME_SOFT,
    HRTIMER_BASE_TAI_SOFT,
    HRTIMER_MAX_CLOCK_BASES,
};

#define __hrtimer_clock_base_align ____cacheline_aligned

/**
 * struct hrtimer_clock_base - the timer base for a specific clock
 * @cpu_base:       per cpu clock base
 * @index:      clock type index for per_cpu support when moving a
 *          timer to a base on another cpu.
 * @clockid:        clock id for per_cpu support
 * @seq:        seqcount around __run_hrtimer
 * @running:        pointer to the currently running hrtimer
 * @active:     red black tree root node for the active timers
 * @get_time:       function to retrieve the current time of the clock
 * @offset:     offset of this clock to the monotonic base
 */
struct hrtimer_clock_base {
    struct hrtimer_cpu_base *cpu_base;
    unsigned int    index;
    clockid_t       clockid;
    seqcount_raw_spinlock_t seq;
    struct hrtimer  *running;
    struct timerqueue_head  active;
    ktime_t         (*get_time)(void);
    ktime_t         offset;
} __hrtimer_clock_base_align;

/**
 * struct hrtimer_cpu_base - the per cpu clock bases
 * @lock:       lock protecting the base and associated clock bases
 *          and timers
 * @cpu:        cpu number
 * @active_bases:   Bitfield to mark bases with active timers
 * @clock_was_set_seq:  Sequence counter of clock was set events
 * @hres_active:    State of high resolution mode
 * @in_hrtirq:      hrtimer_interrupt() is currently executing
 * @hang_detected:  The last hrtimer interrupt detected a hang
 * @softirq_activated:  displays, if the softirq is raised - update of softirq
 *          related settings is not required then.
 * @nr_events:      Total number of hrtimer interrupt events
 * @nr_retries:     Total number of hrtimer interrupt retries
 * @nr_hangs:       Total number of hrtimer interrupt hangs
 * @max_hang_time:  Maximum time spent in hrtimer_interrupt
 * @softirq_expiry_lock: Lock which is taken while softirq based hrtimer are
 *           expired
 * @timer_waiters:  A hrtimer_cancel() invocation waits for the timer
 *          callback to finish.
 * @expires_next:   absolute time of the next event, is required for remote
 *          hrtimer enqueue; it is the total first expiry time (hard
 *          and soft hrtimer are taken into account)
 * @next_timer:     Pointer to the first expiring timer
 * @softirq_expires_next: Time to check, if soft queues needs also to be expired
 * @softirq_next_timer: Pointer to the first expiring softirq based timer
 * @clock_base:     array of clock bases for this cpu
 *
 * Note: next_timer is just an optimization for __remove_hrtimer().
 *   Do not dereference the pointer because it is not reliable on
 *   cross cpu removals.
 */
struct hrtimer_cpu_base {
    raw_spinlock_t          lock;
    unsigned int            cpu;
    unsigned int            active_bases;
    unsigned int            clock_was_set_seq;
    unsigned int            hres_active     : 1,
                            in_hrtirq       : 1,
                            hang_detected       : 1,
                            softirq_activated       : 1;
    unsigned int            nr_events;
    unsigned short          nr_retries;
    unsigned short          nr_hangs;
    unsigned int            max_hang_time;
    ktime_t                 expires_next;
    struct hrtimer          *next_timer;
    ktime_t                 softirq_expires_next;
    struct hrtimer          *softirq_next_timer;
    struct hrtimer_clock_base   clock_base[HRTIMER_MAX_CLOCK_BASES];
} ____cacheline_aligned;

/*
 * Return values for the callback function
 */
enum hrtimer_restart {
    HRTIMER_NORESTART,  /* Timer is not restarted */
    HRTIMER_RESTART,    /* Timer must be restarted */
};

/* Initialize timers: */
extern void hrtimer_init(struct hrtimer *timer, clockid_t which_clock,
                         enum hrtimer_mode mode);

/* Bootup initialization: */
extern void __init hrtimers_init(void);

/* Basic timer operations: */
extern void
hrtimer_start_range_ns(struct hrtimer *timer, ktime_t tim,
                       u64 range_ns, const enum hrtimer_mode mode);

/**
 * hrtimer_start - (re)start an hrtimer
 * @timer:  the timer to be added
 * @tim:    expiry time
 * @mode:   timer mode: absolute (HRTIMER_MODE_ABS) or
 *      relative (HRTIMER_MODE_REL), and pinned (HRTIMER_MODE_PINNED);
 *      softirq based mode is considered for debug purpose only!
 */
static inline
void hrtimer_start(struct hrtimer *timer, ktime_t tim,
                   const enum hrtimer_mode mode)
{
    hrtimer_start_range_ns(timer, tim, 0, mode);
}

/**
 * hrtimer_forward_now - forward the timer expiry so it expires after now
 * @timer:  hrtimer to forward
 * @interval:   the interval to forward
 *
 * Forward the timer expiry so it will expire after the current time
 * of the hrtimer clock base. Returns the number of overruns.
 *
 * Can be safely called from the callback function of @timer. If
 * called from other contexts @timer must neither be enqueued nor
 * running the callback and the caller needs to take care of
 * serialization.
 *
 * Note: This only updates the timer expiry value and does not requeue
 * the timer.
 */
static inline u64 hrtimer_forward_now(struct hrtimer *timer,
                                      ktime_t interval)
{
    //return hrtimer_forward(timer, timer->base->get_time(), interval);
    panic("%s: END!\n", __func__);
}

int hrtimers_prepare_cpu(unsigned int cpu);
int hrtimers_dead_cpu(unsigned int cpu);

static inline
void hrtimer_set_expires_range_ns(struct hrtimer *timer, ktime_t time,
                                  u64 delta)
{
    timer->_softexpires = time;
    timer->node.expires = ktime_add_safe(time, ns_to_ktime(delta));
}

static inline ktime_t hrtimer_get_expires(const struct hrtimer *timer)
{
    return timer->node.expires;
}

static inline s64 hrtimer_get_expires_tv64(const struct hrtimer *timer)
{
    return timer->node.expires;
}
static inline
s64 hrtimer_get_softexpires_tv64(const struct hrtimer *timer)
{
    return timer->_softexpires;
}

#endif /* _LINUX_HRTIMER_H */
