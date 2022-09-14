/*
 * cpuidle.c - core cpuidle infrastructure
 *
 * (C) 2006-2007 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *               Shaohua Li <shaohua.li@intel.com>
 *               Adam Belay <abelay@novell.com>
 *
 * This code is licenced under the GPL.
 */

#include <linux/clockchips.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#if 0
#include <linux/notifier.h>
#include <linux/pm_qos.h>
#endif
#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/module.h>
//#include <linux/suspend.h>
#include <linux/tick.h>
#include <linux/mmu_context.h>
//#include <trace/events/power.h>

//#include "cpuidle.h"

DEFINE_PER_CPU(struct cpuidle_device *, cpuidle_devices);
DEFINE_PER_CPU(struct cpuidle_device, cpuidle_dev);

DEFINE_MUTEX(cpuidle_lock);
LIST_HEAD(cpuidle_detected_devices);

static int off __read_mostly;
static int initialized __read_mostly;

bool cpuidle_not_available(struct cpuidle_driver *drv,
                           struct cpuidle_device *dev)
{
    return off || !initialized || !drv || !dev || !dev->enabled;
}
