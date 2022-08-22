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
//#include <linux/timer.h>
#include <linux/timerqueue.h>

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

#endif /* _LINUX_HRTIMER_H */
