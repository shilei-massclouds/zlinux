/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  pm.h - Power management interface
 *
 *  Copyright (C) 2000 Andrew Henroid
 */

#ifndef _LINUX_PM_H
#define _LINUX_PM_H

#include <linux/export.h>
#include <linux/list.h>
#if 0
#include <linux/workqueue.h>
#endif
#include <linux/spinlock.h>
#include <linux/wait.h>
#if 0
#include <linux/timer.h>
#include <linux/hrtimer.h>
#endif
#include <linux/completion.h>

struct device;

/*
 * Callbacks for platform drivers to implement.
 */
extern void (*pm_power_off)(void);
extern void (*pm_power_off_prepare)(void);

typedef struct pm_message {
    int event;
} pm_message_t;

struct dev_pm_ops {
    int (*prepare)(struct device *dev);
    void (*complete)(struct device *dev);
    int (*suspend)(struct device *dev);
    int (*resume)(struct device *dev);
    int (*freeze)(struct device *dev);
    int (*thaw)(struct device *dev);
    int (*poweroff)(struct device *dev);
    int (*restore)(struct device *dev);
    int (*suspend_late)(struct device *dev);
    int (*resume_early)(struct device *dev);
    int (*freeze_late)(struct device *dev);
    int (*thaw_early)(struct device *dev);
    int (*poweroff_late)(struct device *dev);
    int (*restore_early)(struct device *dev);
    int (*suspend_noirq)(struct device *dev);
    int (*resume_noirq)(struct device *dev);
    int (*freeze_noirq)(struct device *dev);
    int (*thaw_noirq)(struct device *dev);
    int (*poweroff_noirq)(struct device *dev);
    int (*restore_noirq)(struct device *dev);
    int (*runtime_suspend)(struct device *dev);
    int (*runtime_resume)(struct device *dev);
    int (*runtime_idle)(struct device *dev);
};

/*
 * Device run-time power management status.
 *
 * These status labels are used internally by the PM core to indicate the
 * current status of a device with respect to the PM core operations.  They do
 * not reflect the actual power state of the device or its status as seen by the
 * driver.
 *
 * RPM_ACTIVE       Device is fully operational.  Indicates that the device
 *          bus type's ->runtime_resume() callback has completed
 *          successfully.
 *
 * RPM_SUSPENDED    Device bus type's ->runtime_suspend() callback has
 *          completed successfully.  The device is regarded as
 *          suspended.
 *
 * RPM_RESUMING     Device bus type's ->runtime_resume() callback is being
 *          executed.
 *
 * RPM_SUSPENDING   Device bus type's ->runtime_suspend() callback is being
 *          executed.
 */

enum rpm_status {
    RPM_INVALID = -1,
    RPM_ACTIVE = 0,
    RPM_RESUMING,
    RPM_SUSPENDED,
    RPM_SUSPENDING,
};

#endif /* _LINUX_PM_H */
