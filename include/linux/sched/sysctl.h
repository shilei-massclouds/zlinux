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

#endif /* _LINUX_SCHED_SYSCTL_H */
