/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_CLOCK_H
#define _LINUX_SCHED_CLOCK_H

#include <linux/smp.h>

static inline void enable_sched_clock_irqtime(void) {}
static inline void disable_sched_clock_irqtime(void) {}

#endif /* _LINUX_SCHED_CLOCK_H */
