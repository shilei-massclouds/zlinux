/*
 * cpuidle.h - a generic framework for CPU idle power management
 *
 * (C) 2007 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *          Shaohua Li <shaohua.li@intel.com>
 *          Adam Belay <abelay@novell.com>
 *
 * This code is licenced under the GPL.
 */

#ifndef _LINUX_CPUIDLE_H
#define _LINUX_CPUIDLE_H

#include <linux/percpu.h>
#include <linux/list.h>
#include <linux/hrtimer.h>

#define CPUIDLE_STATE_MAX   10
#define CPUIDLE_NAME_LEN    16
#define CPUIDLE_DESC_LEN    32

struct module;

struct cpuidle_device;
struct cpuidle_driver;

struct cpuidle_state_usage {
    unsigned long long  disable;
    unsigned long long  usage;
    u64         time_ns;
    unsigned long long  above; /* Number of times it's been too deep */
    unsigned long long  below; /* Number of times it's been too shallow */
    unsigned long long  rejected; /* Number of times idle entry was rejected */
};

struct cpuidle_device {
    unsigned int        registered:1;
    unsigned int        enabled:1;
    unsigned int        poll_time_limit:1;
    unsigned int        cpu;
    ktime_t         next_hrtimer;

    int         last_state_idx;
    u64         last_residency_ns;
    u64         poll_limit_ns;
    u64         forced_idle_latency_limit_ns;
    struct cpuidle_state_usage  states_usage[CPUIDLE_STATE_MAX];
    struct cpuidle_state_kobj *kobjs[CPUIDLE_STATE_MAX];
    struct cpuidle_driver_kobj *kobj_driver;
    struct cpuidle_device_kobj *kobj_dev;
    struct list_head    device_list;
};

extern struct cpuidle_driver *
cpuidle_get_cpu_driver(struct cpuidle_device *dev);

DECLARE_PER_CPU(struct cpuidle_device *, cpuidle_devices);

static inline struct cpuidle_device *cpuidle_get_device(void)
{return __this_cpu_read(cpuidle_devices); }

#endif /* _LINUX_CPUIDLE_H */
