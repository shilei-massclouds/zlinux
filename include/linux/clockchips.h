/* SPDX-License-Identifier: GPL-2.0 */
/*  linux/include/linux/clockchips.h
 *
 *  This file contains the structure definitions for clockchips.
 *
 *  If you are not a clockchip, or the time of day code, you should
 *  not be including this file!
 */
#ifndef _LINUX_CLOCKCHIPS_H
#define _LINUX_CLOCKCHIPS_H

#include <linux/clocksource.h>
#include <linux/cpumask.h>
#include <linux/ktime.h>
//#include <linux/notifier.h>

/*
 * Clock event features
 */
#define CLOCK_EVT_FEAT_PERIODIC     0x000001
#define CLOCK_EVT_FEAT_ONESHOT      0x000002
#define CLOCK_EVT_FEAT_KTIME        0x000004

/*
 * x86(64) specific (mis)features:
 *
 * - Clockevent source stops in C3 State and needs broadcast support.
 * - Local APIC timer is used as a dummy device.
 */
#define CLOCK_EVT_FEAT_C3STOP       0x000008
#define CLOCK_EVT_FEAT_DUMMY        0x000010

/*
 * Core shall set the interrupt affinity dynamically in broadcast mode
 */
#define CLOCK_EVT_FEAT_DYNIRQ       0x000020
#define CLOCK_EVT_FEAT_PERCPU       0x000040

/*
 * Clockevent device is based on a hrtimer for broadcast
 */
#define CLOCK_EVT_FEAT_HRTIMER     0x000080

struct clock_event_device;
struct module;

/*
 * Possible states of a clock event device.
 *
 * DETACHED:    Device is not used by clockevents core. Initial state or can be
 *      reached from SHUTDOWN.
 * SHUTDOWN:    Device is powered-off. Can be reached from PERIODIC or ONESHOT.
 * PERIODIC:    Device is programmed to generate events periodically. Can be
 *      reached from DETACHED or SHUTDOWN.
 * ONESHOT: Device is programmed to generate event only once. Can be reached
 *      from DETACHED or SHUTDOWN.
 * ONESHOT_STOPPED: Device was programmed in ONESHOT mode and is temporarily
 *          stopped.
 */
enum clock_event_state {
    CLOCK_EVT_STATE_DETACHED,
    CLOCK_EVT_STATE_SHUTDOWN,
    CLOCK_EVT_STATE_PERIODIC,
    CLOCK_EVT_STATE_ONESHOT,
    CLOCK_EVT_STATE_ONESHOT_STOPPED,
};

/**
 * struct clock_event_device - clock event device descriptor
 * @event_handler:  Assigned by the framework to be called by the low
 *          level handler of the event source
 * @set_next_event: set next event function using a clocksource delta
 * @set_next_ktime: set next event function using a direct ktime value
 * @next_event:     local storage for the next event in oneshot mode
 * @max_delta_ns:   maximum delta value in ns
 * @min_delta_ns:   minimum delta value in ns
 * @mult:       nanosecond to cycles multiplier
 * @shift:      nanoseconds to cycles divisor (power of two)
 * @state_use_accessors:current state of the device, assigned by the core code
 * @features:       features
 * @retries:        number of forced programming retries
 * @set_state_periodic: switch state to periodic
 * @set_state_oneshot:  switch state to oneshot
 * @set_state_oneshot_stopped: switch state to oneshot_stopped
 * @set_state_shutdown: switch state to shutdown
 * @tick_resume:    resume clkevt device
 * @broadcast:      function to broadcast events
 * @min_delta_ticks:    minimum delta value in ticks stored for reconfiguration
 * @max_delta_ticks:    maximum delta value in ticks stored for reconfiguration
 * @name:       ptr to clock event name
 * @rating:     variable to rate clock event devices
 * @irq:        IRQ number (only for non CPU local devices)
 * @bound_on:       Bound on CPU
 * @cpumask:        cpumask to indicate for which CPUs this device works
 * @list:       list head for the management code
 * @owner:      module reference
 */
struct clock_event_device {
    void        (*event_handler)(struct clock_event_device *);
    int         (*set_next_event)(unsigned long evt,
                                  struct clock_event_device *);
    int         (*set_next_ktime)(ktime_t expires, struct clock_event_device *);
    ktime_t     next_event;
    u64         max_delta_ns;
    u64         min_delta_ns;
    u32         mult;
    u32         shift;
    enum clock_event_state  state_use_accessors;
    unsigned int        features;
    unsigned long       retries;

    int         (*set_state_periodic)(struct clock_event_device *);
    int         (*set_state_oneshot)(struct clock_event_device *);
    int         (*set_state_oneshot_stopped)(struct clock_event_device *);
    int         (*set_state_shutdown)(struct clock_event_device *);
    int         (*tick_resume)(struct clock_event_device *);

    void            (*broadcast)(const struct cpumask *mask);
    void            (*suspend)(struct clock_event_device *);
    void            (*resume)(struct clock_event_device *);
    unsigned long       min_delta_ticks;
    unsigned long       max_delta_ticks;

    const char      *name;
    int         rating;
    int         irq;
    int         bound_on;
    const struct cpumask    *cpumask;
    struct list_head    list;
    struct module       *owner;
} ____cacheline_aligned;

/*
 * Clock event features
 */
#define CLOCK_EVT_FEAT_PERIODIC     0x000001
#define CLOCK_EVT_FEAT_ONESHOT      0x000002
#define CLOCK_EVT_FEAT_KTIME        0x000004

extern void clockevents_config_and_register(struct clock_event_device *dev,
                                            u32 freq, unsigned long min_delta,
                                            unsigned long max_delta);

static inline void
clockevents_calc_mult_shift(struct clock_event_device *ce, u32 freq, u32 maxsec)
{
    return clocks_calc_mult_shift(&ce->mult, &ce->shift, NSEC_PER_SEC, freq,
                                  maxsec);
}

/* Helpers to verify state of a clockevent device */
static inline bool clockevent_state_detached(struct clock_event_device *dev)
{
    return dev->state_use_accessors == CLOCK_EVT_STATE_DETACHED;
}

static inline bool clockevent_state_oneshot(struct clock_event_device *dev)
{
    return dev->state_use_accessors == CLOCK_EVT_STATE_ONESHOT;
}

extern void tick_broadcast(const struct cpumask *mask);

static inline bool clockevent_state_shutdown(struct clock_event_device *dev)
{
    return dev->state_use_accessors == CLOCK_EVT_STATE_SHUTDOWN;
}

#endif /* _LINUX_CLOCKCHIPS_H */
