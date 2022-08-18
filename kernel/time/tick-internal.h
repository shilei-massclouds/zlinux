/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tick internal variable and functions used by low/high res code
 */
//#include <linux/hrtimer.h>
#include <linux/tick.h>

//#include "timekeeping.h"
#include "tick-sched.h"

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
