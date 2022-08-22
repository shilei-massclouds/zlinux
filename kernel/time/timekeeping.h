/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KERNEL_TIME_TIMEKEEPING_H
#define _KERNEL_TIME_TIMEKEEPING_H
/*
 * Internal interfaces for kernel/time/
 */
extern void update_wall_time(void);

extern void do_timer(unsigned long ticks);

#endif /* _KERNEL_TIME_TIMEKEEPING_H */
