/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Tick related global functions
 */
#ifndef _LINUX_TICK_H
#define _LINUX_TICK_H

#include <linux/clockchips.h>
#include <linux/irqflags.h>
#include <linux/percpu.h>
//#include <linux/context_tracking_state.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>

extern bool tick_nohz_enabled;
extern bool tick_nohz_tick_stopped(void);
extern bool tick_nohz_tick_stopped_cpu(int cpu);
extern void tick_nohz_idle_stop_tick(void);
extern void tick_nohz_idle_retain_tick(void);
extern void tick_nohz_idle_restart_tick(void);
extern void tick_nohz_idle_enter(void);
extern void tick_nohz_idle_exit(void);
extern void tick_nohz_irq_exit(void);
extern bool tick_nohz_idle_got_tick(void);
extern ktime_t tick_nohz_get_next_hrtimer(void);
extern ktime_t tick_nohz_get_sleep_length(ktime_t *delta_next);
extern unsigned long tick_nohz_get_idle_calls(void);
extern unsigned long tick_nohz_get_idle_calls_cpu(int cpu);
extern u64 get_cpu_idle_time_us(int cpu, u64 *last_update_time);
extern u64 get_cpu_iowait_time_us(int cpu, u64 *last_update_time);

static inline void tick_nohz_idle_stop_tick_protected(void)
{
    local_irq_disable();
    tick_nohz_idle_stop_tick();
    local_irq_enable();
}

#endif /* _LINUX_TICK_H */
