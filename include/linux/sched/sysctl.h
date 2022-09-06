/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_SYSCTL_H
#define _LINUX_SCHED_SYSCTL_H

#include <linux/types.h>

struct ctl_table;

enum sched_tunable_scaling {
    SCHED_TUNABLESCALING_NONE,
    SCHED_TUNABLESCALING_LOG,
    SCHED_TUNABLESCALING_LINEAR,
    SCHED_TUNABLESCALING_END,
};

#define NUMA_BALANCING_DISABLED         0x0
#define NUMA_BALANCING_NORMAL           0x1
#define NUMA_BALANCING_MEMORY_TIERING   0x2

#define sysctl_numa_balancing_mode  0

extern int sched_rr_timeslice;

#endif /* _LINUX_SCHED_SYSCTL_H */
