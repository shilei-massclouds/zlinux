/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tick internal variable and functions used by low/high res code
 */
#include <linux/hrtimer.h>
#include <linux/tick.h>

#include "timekeeping.h"
#include "tick-sched.h"

#define TICK_DO_TIMER_NONE -1
#define TICK_DO_TIMER_BOOT -2

extern int tick_do_timer_cpu __read_mostly;

DECLARE_PER_CPU(struct tick_device, tick_cpu_device);

extern void tick_setup_oneshot(struct clock_event_device *newdev,
                               void (*handler)(struct clock_event_device *),
                               ktime_t nextevt);
extern int tick_program_event(ktime_t expires, int force);
extern void tick_oneshot_notify(void);
extern int tick_switch_to_oneshot(void (*handler)(struct clock_event_device *));
extern void tick_resume_oneshot(void);
static inline bool tick_oneshot_possible(void) { return true; }
extern int tick_oneshot_mode_active(void);
extern void tick_clock_notify(void);
extern int tick_check_oneshot_change(int allow_nohz);
extern int tick_init_highres(void);

extern int tick_device_uses_broadcast(struct clock_event_device *dev, int cpu);

/* Since jiffies uses a simple TICK_NSEC multiplier
 * conversion, the .shift value could be zero. However
 * this would make NTP adjustments impossible as they are
 * in units of 1/2^.shift. Thus we use JIFFIES_SHIFT to
 * shift both the nominator and denominator the same
 * amount, and give ntp adjustments in units of 1/2^8
 *
 * The value 8 is somewhat carefully chosen, as anything
 * larger can result in overflows. TICK_NSEC grows as HZ
 * shrinks, so values greater than 8 overflow 32bits when
 * HZ=100.
 */
#if HZ < 34
#define JIFFIES_SHIFT   6
#elif HZ < 67
#define JIFFIES_SHIFT   7
#else
#define JIFFIES_SHIFT   8
#endif

extern void tick_check_new_device(struct clock_event_device *dev);

static inline void clockevent_set_state(struct clock_event_device *dev,
                                        enum clock_event_state state)
{
    dev->state_use_accessors = state;
}

static inline
enum clock_event_state clockevent_get_state(struct clock_event_device *dev)
{
    return dev->state_use_accessors;
}

extern void tick_install_broadcast_device(struct clock_event_device *dev,
                                          int cpu);

extern int tick_is_broadcast_device(struct clock_event_device *dev);

extern void clockevents_shutdown(struct clock_event_device *dev);

extern void clockevents_exchange_device(struct clock_event_device *old,
                                        struct clock_event_device *new);

extern void clockevents_handle_noop(struct clock_event_device *dev);

/* Check, if the device is functional or a dummy for broadcast */
static inline int tick_device_is_functional(struct clock_event_device *dev)
{
    return !(dev->features & CLOCK_EVT_FEAT_DUMMY);
}

extern void tick_set_periodic_handler(struct clock_event_device *dev,
                                      int broadcast);

extern void clockevents_switch_state(struct clock_event_device *dev,
                                     enum clock_event_state state);

extern int clockevents_program_event(struct clock_event_device *dev,
                                     ktime_t expires, bool force);

extern void tick_handle_periodic(struct clock_event_device *dev);

extern int tick_broadcast_oneshot_active(void);

void clock_was_set_delayed(void);
