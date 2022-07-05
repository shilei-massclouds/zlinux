// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/base/dd.c - The core device/driver interactions.
 *
 * This file contains the (sometimes tricky) code that controls the
 * interactions between devices and drivers, which primarily includes
 * driver binding and unbinding.
 *
 * All of this code used to exist in drivers/base/bus.c, but was
 * relocated to here in the name of compartmentalization (since it wasn't
 * strictly code just for the 'struct bus_type'.
 *
 * Copyright (c) 2002-5 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 * Copyright (c) 2007-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2007-2009 Novell Inc.
 */

#include <linux/device.h>
#if 0
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/dma-map-ops.h>
#endif
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#if 0
#include <linux/async.h>
#include <linux/pm_runtime.h>
#include <linux/pinctrl/devinfo.h>
#endif
#include <linux/slab.h>

#include "base.h"

static atomic_t probe_count = ATOMIC_INIT(0);
#if 0
static DECLARE_WAIT_QUEUE_HEAD(probe_waitqueue);
#endif

static atomic_t deferred_trigger_count = ATOMIC_INIT(0);

void driver_deferred_probe_add(struct device *dev)
{
    if (!dev->can_match)
        return;

    panic("%s: END!\n", __func__);
#if 0
    mutex_lock(&deferred_probe_mutex);
    if (list_empty(&dev->p->deferred_probe)) {
        pr_debug("Added to deferred list\n");
        list_add_tail(&dev->p->deferred_probe, &deferred_probe_pending_list);
    }
    mutex_unlock(&deferred_probe_mutex);
#endif
}

/*
 * __device_driver_lock - acquire locks needed to manipulate dev->drv
 * @dev: Device we will update driver info for
 * @parent: Parent device. Needed if the bus requires parent lock
 *
 * This function will take the required locks for manipulating dev->drv.
 * Normally this will just be the @dev lock, but when called for a USB
 * interface, @parent lock will be held as well.
 */
static void __device_driver_lock(struct device *dev, struct device *parent)
{
    if (parent && dev->bus->need_parent_lock)
        device_lock(parent);
    device_lock(dev);
}

/*
 * __device_driver_unlock - release locks needed to manipulate dev->drv
 * @dev: Device we will update driver info for
 * @parent: Parent device. Needed if the bus requires parent lock
 *
 * This function will release the required locks for manipulating dev->drv.
 * Normally this will just be the @dev lock, but when called for a
 * USB interface, @parent lock will be released as well.
 */
static void __device_driver_unlock(struct device *dev, struct device *parent)
{
    device_unlock(dev);
    if (parent && dev->bus->need_parent_lock)
        device_unlock(parent);
}

static int really_probe(struct device *dev, struct device_driver *drv)
{
    panic("%s: END!\n", __func__);
}

static int __driver_probe_device(struct device_driver *drv, struct device *dev)
{
    int ret = 0;

    if (dev->p->dead || !device_is_registered(dev))
        return -ENODEV;
    if (dev->driver)
        return -EBUSY;

    dev->can_match = true;
    pr_debug("bus: '%s': %s: matched device %s with driver %s\n",
             drv->bus->name, __func__, dev_name(dev), drv->name);

#if 0
    pm_runtime_get_suppliers(dev);
    if (dev->parent)
        pm_runtime_get_sync(dev->parent);

    pm_runtime_barrier(dev);
#endif

    ret = really_probe(dev, drv);

#if 0
    pm_request_idle(dev);

    if (dev->parent)
        pm_runtime_put(dev->parent);

    pm_runtime_put_suppliers(dev);
#endif
    return ret;
}

/**
 * driver_probe_device - attempt to bind device & driver together
 * @drv: driver to bind a device to
 * @dev: device to try to bind to the driver
 *
 * This function returns -ENODEV if the device is not registered, -EBUSY if it
 * already has a driver, 0 if the device is bound successfully and a positive
 * (inverted) error code for failures from the ->probe method.
 *
 * This function must be called with @dev lock held.  When called for a
 * USB interface, @dev->parent lock must be held as well.
 *
 * If the device has a parent, runtime-resume the parent before driver probing.
 */
static int driver_probe_device(struct device_driver *drv, struct device *dev)
{
    int trigger_count = atomic_read(&deferred_trigger_count);
    int ret;

    atomic_inc(&probe_count);
    ret = __driver_probe_device(drv, dev);
    if (ret == -EPROBE_DEFER || ret == EPROBE_DEFER) {
        panic("NOT SUPPORT EPROBE_DEFER or EPROBE_DEFER!\n");
#if 0
        driver_deferred_probe_add(dev);

        /*
         * Did a trigger occur while probing? Need to re-trigger if yes
         */
        if (trigger_count != atomic_read(&deferred_trigger_count) &&
            !defer_all_probes)
            driver_deferred_probe_trigger();
#endif
    }
    atomic_dec(&probe_count);
#if 0
    wake_up_all(&probe_waitqueue);
#endif
    return ret;
}

static int __driver_attach(struct device *dev, void *data)
{
    struct device_driver *drv = data;
    int ret;

    /*
     * Lock device and try to bind to it. We drop the error
     * here and always return 0, because we need to keep trying
     * to bind to devices and some drivers will return an error
     * simply if it didn't support the device.
     *
     * driver_probe_device() will spit a warning if there
     * is an error.
     */

    ret = driver_match_device(drv, dev);
    if (ret == 0) {
        /* no match */
        return 0;
    } else if (ret == -EPROBE_DEFER) {
        pr_debug("Device match requests probe deferral\n");
        dev->can_match = true;
        driver_deferred_probe_add(dev);
    } else if (ret < 0) {
        pr_debug("Bus failed to match device: %d\n", ret);
        return ret;
    } /* ret > 0 means positive match */

#if 0
    if (driver_allows_async_probing(drv)) {
        /*
         * Instead of probing the device synchronously we will
         * probe it asynchronously to allow for more parallelism.
         *
         * We only take the device lock here in order to guarantee
         * that the dev->driver and async_driver fields are protected
         */
        dev_dbg(dev, "probing driver %s asynchronously\n", drv->name);
        device_lock(dev);
        if (!dev->driver) {
            get_device(dev);
            dev->p->async_driver = drv;
            async_schedule_dev(__driver_attach_async_helper, dev);
        }
        device_unlock(dev);
        return 0;
    }
#endif

    __device_driver_lock(dev, dev->parent);
    driver_probe_device(drv, dev);
    __device_driver_unlock(dev, dev->parent);

    panic("%s: END!\n", __func__);
    return 0;
}

/**
 * driver_attach - try to bind driver to devices.
 * @drv: driver.
 *
 * Walk the list of devices that the bus has on it and try to
 * match the driver with each one.  If driver_probe_device()
 * returns 0 and the @dev->driver is set, we've found a
 * compatible pair.
 */
int driver_attach(struct device_driver *drv)
{
    return bus_for_each_dev(drv->bus, NULL, drv, __driver_attach);
}
EXPORT_SYMBOL_GPL(driver_attach);
