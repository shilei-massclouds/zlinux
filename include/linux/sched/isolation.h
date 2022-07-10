#ifndef _LINUX_SCHED_ISOLATION_H
#define _LINUX_SCHED_ISOLATION_H

#include <linux/cpumask.h>
#include <linux/init.h>
#if 0
#include <linux/tick.h>
#endif

enum hk_type {
    HK_TYPE_TIMER,
    HK_TYPE_RCU,
    HK_TYPE_MISC,
    HK_TYPE_SCHED,
    HK_TYPE_TICK,
    HK_TYPE_DOMAIN,
    HK_TYPE_WQ,
    HK_TYPE_MANAGED_IRQ,
    HK_TYPE_KTHREAD,
    HK_TYPE_MAX
};

extern bool housekeeping_enabled(enum hk_type type);

#endif /* _LINUX_SCHED_ISOLATION_H */
