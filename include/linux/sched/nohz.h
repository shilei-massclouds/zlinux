/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_NOHZ_H
#define _LINUX_SCHED_NOHZ_H

/*
 * This is the interface between the scheduler and nohz/dynticks:
 */

extern void nohz_balance_enter_idle(int cpu);
extern int get_nohz_timer_target(void);

void calc_load_nohz_start(void);
void calc_load_nohz_remote(struct rq *rq);
void calc_load_nohz_stop(void);

extern void wake_up_nohz_cpu(int cpu);

#endif /* _LINUX_SCHED_NOHZ_H */
