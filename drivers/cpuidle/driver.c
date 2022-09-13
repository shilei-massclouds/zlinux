/*
 * driver.c - driver support
 *
 * (C) 2006-2007 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *               Shaohua Li <shaohua.li@intel.com>
 *               Adam Belay <abelay@novell.com>
 *
 * This code is licenced under the GPL.
 */

#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/idle.h>
#include <linux/cpuidle.h>
#include <linux/cpumask.h>
#include <linux/tick.h>
#include <linux/cpu.h>

//#include "cpuidle.h"

DEFINE_SPINLOCK(cpuidle_driver_lock);

static DEFINE_PER_CPU(struct cpuidle_driver *, cpuidle_drivers);

/**
 * __cpuidle_get_cpu_driver - return the cpuidle driver tied to a CPU.
 * @cpu: the CPU handled by the driver
 *
 * Returns a pointer to struct cpuidle_driver or NULL if no driver has been
 * registered for @cpu.
 */
static struct cpuidle_driver *__cpuidle_get_cpu_driver(int cpu)
{
    return per_cpu(cpuidle_drivers, cpu);
}

/**
 * cpuidle_get_cpu_driver - return the driver registered for a CPU.
 * @dev: a valid pointer to a struct cpuidle_device
 *
 * Returns a struct cpuidle_driver pointer, or NULL if no driver is registered
 * for the CPU associated with @dev.
 */
struct cpuidle_driver *
cpuidle_get_cpu_driver(struct cpuidle_device *dev)
{
    if (!dev)
        return NULL;

    return __cpuidle_get_cpu_driver(dev->cpu);
}
EXPORT_SYMBOL_GPL(cpuidle_get_cpu_driver);
