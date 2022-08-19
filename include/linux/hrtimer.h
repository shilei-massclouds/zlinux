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
