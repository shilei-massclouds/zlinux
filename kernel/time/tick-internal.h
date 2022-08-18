/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tick internal variable and functions used by low/high res code
 */
//#include <linux/hrtimer.h>
//#include <linux/tick.h>

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
