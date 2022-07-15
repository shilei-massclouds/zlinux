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

/*
 * In some cases, like suspend to RAM or hibernation, It might be reasonable
 * to prohibit probing of devices as it could be unsafe.
 * Once defer_all_probes is true all drivers probes will be forcibly deferred.
 */
static bool defer_all_probes;

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

static void device_remove(struct device *dev)
{
#if 0
    device_remove_file(dev, &dev_attr_state_synced);
    device_remove_groups(dev, dev->driver->dev_groups);
#endif

    if (dev->bus && dev->bus->remove)
        dev->bus->remove(dev);
    else if (dev->driver->remove)
        dev->driver->remove(dev);
}

static int call_driver_probe(struct device *dev, struct device_driver *drv)
{
    int ret = 0;

    if (dev->bus->probe)
        ret = dev->bus->probe(dev);
    else if (drv->probe)
        ret = drv->probe(dev);

    switch (ret) {
    case 0:
        break;
    case -EPROBE_DEFER:
        /* Driver requested deferred probing */
        pr_debug("Driver %s requests probe deferral\n", drv->name);
        break;
    case -ENODEV:
    case -ENXIO:
        pr_debug("%s: probe of %s rejects match %d\n",
                 drv->name, dev_name(dev), ret);
        break;
    default:
        /* driver matched but the probe failed */
        pr_warn("%s: probe of %s failed with error %d\n",
                drv->name, dev_name(dev), ret);
        break;
    }

    return ret;
}

static inline bool dev_has_sync_state(struct device *dev)
{
    if (!dev)
        return false;
    if (dev->driver && dev->driver->sync_state)
        return true;
    if (dev->bus && dev->bus->sync_state)
        return true;
    return false;
}

/**
 * device_is_bound() - Check if device is bound to a driver
 * @dev: device to check
 *
 * Returns true if passed device has already finished probing successfully
 * against a driver.
 *
 * This function must be called with the device lock held.
 */
bool device_is_bound(struct device *dev)
{
    return dev->p && klist_node_attached(&dev->p->knode_driver);
}

static void driver_bound(struct device *dev)
{
    if (device_is_bound(dev)) {
        pr_warn("%s: device %s already bound\n",
                __func__, kobject_name(&dev->kobj));
        return;
    }

    pr_info("driver: '%s': %s: bound to device '%s'\n", dev->driver->name,
            __func__, dev_name(dev));

    klist_add_tail(&dev->p->knode_driver, &dev->driver->p->klist_devices);
#if 0
    device_links_driver_bound(dev);

    device_pm_check_callbacks(dev);

    /*
     * Make sure the device is no longer in one of the deferred lists and
     * kick off retrying all pending devices
     */
    driver_deferred_probe_del(dev);
    driver_deferred_probe_trigger();

    if (dev->bus)
        blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
                         BUS_NOTIFY_BOUND_DRIVER, dev);

    kobject_uevent(&dev->kobj, KOBJ_BIND);
#endif
}

static int really_probe(struct device *dev, struct device_driver *drv)
{
    int ret;

    if (defer_all_probes) {
        /*
         * Value of defer_all_probes can be set only by
         * device_block_probing() which, in turn, will call
         * wait_for_device_probe() right after that to avoid any races.
         */
        pr_debug("Driver %s force probe deferral\n", drv->name);
        return -EPROBE_DEFER;
    }

#if 0
    ret = device_links_check_suppliers(dev);
    if (ret)
        return ret;
#endif

    pr_debug("bus: '%s': %s: probing driver %s with device %s\n",
             drv->bus->name, __func__, drv->name, dev_name(dev));
    if (!list_empty(&dev->devres_head)) {
        pr_err("Resources present before probing\n");
        ret = -EBUSY;
        goto done;
    }

re_probe:
    dev->driver = drv;

    if (dev->bus->dma_configure) {
        ret = dev->bus->dma_configure(dev);
        if (ret)
            goto pinctrl_bind_failed;
    }

#if 0
    ret = driver_sysfs_add(dev);
    if (ret) {
        pr_err("%s: driver_sysfs_add(%s) failed\n",
               __func__, dev_name(dev));
        goto sysfs_failed;
    }

    if (dev->pm_domain && dev->pm_domain->activate) {
        ret = dev->pm_domain->activate(dev);
        if (ret)
            goto probe_failed;
    }
#endif

    ret = call_driver_probe(dev, drv);
    if (ret) {
        /*
         * Return probe errors as positive values so that the callers
         * can distinguish them from other errors.
         */
        ret = -ret;
        goto probe_failed;
    }

#if 0
    ret = device_add_groups(dev, drv->dev_groups);
    if (ret) {
        dev_err(dev, "device_add_groups() failed\n");
        goto dev_groups_failed;
    }
#endif

    if (dev_has_sync_state(dev)) {
#if 0
        ret = device_create_file(dev, &dev_attr_state_synced);
        if (ret) {
            dev_err(dev, "state_synced sysfs add failed\n");
            goto dev_sysfs_state_synced_failed;
        }
#endif
    }

#if 0
    if (dev->pm_domain && dev->pm_domain->sync)
        dev->pm_domain->sync(dev);
#endif

    driver_bound(dev);
    pr_info("bus: '%s': %s: bound device %s to driver %s\n",
            drv->bus->name, __func__, dev_name(dev), drv->name);
    goto done;

dev_sysfs_state_synced_failed:
dev_groups_failed:
    device_remove(dev);
probe_failed:
#if 0
    driver_sysfs_remove(dev);
sysfs_failed:
    if (dev->bus)
        blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
                                     BUS_NOTIFY_DRIVER_NOT_BOUND, dev);
#endif
pinctrl_bind_failed:
#if 0
    device_links_no_driver(dev);
    device_unbind_cleanup(dev);
#endif
done:
    return ret;
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

/**
 * device_bind_driver - bind a driver to one device.
 * @dev: device.
 *
 * Allow manual attachment of a driver to a device.
 * Caller must have already set @dev->driver.
 *
 * Note that this does not modify the bus reference count.
 * Please verify that is accounted for before calling this.
 * (It is ok to call with no other effort from a driver's probe() method.)
 *
 * This function must be called with the device lock held.
 *
 * Callers should prefer to use device_driver_attach() instead.
 */
int device_bind_driver(struct device *dev)
{
    int ret;

#if 0
    ret = driver_sysfs_add(dev);
    if (!ret) {
        device_links_force_bind(dev);
        driver_bound(dev);
    }
    else if (dev->bus)
        blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
                         BUS_NOTIFY_DRIVER_NOT_BOUND, dev);
#endif
    panic("%s: END!\n", __func__);
    return ret;
}
EXPORT_SYMBOL_GPL(device_bind_driver);

struct device_attach_data {
    struct device *dev;

    /*
     * Indicates whether we are considering asynchronous probing or
     * not. Only initial binding after device or driver registration
     * (including deferral processing) may be done asynchronously, the
     * rest is always synchronous, as we expect it is being done by
     * request from userspace.
     */
    bool check_async;

    /*
     * Indicates if we are binding synchronous or asynchronous drivers.
     * When asynchronous probing is enabled we'll execute 2 passes
     * over drivers: first pass doing synchronous probing and second
     * doing asynchronous probing (if synchronous did not succeed -
     * most likely because there was no driver requiring synchronous
     * probing - and we found asynchronous driver during first pass).
     * The 2 passes are done because we can't shoot asynchronous
     * probe for given device and driver from bus_for_each_drv() since
     * driver pointer is not guaranteed to stay valid once
     * bus_for_each_drv() iterates to the next driver on the bus.
     */
    bool want_async;

    /*
     * We'll set have_async to 'true' if, while scanning for matching
     * driver, we'll encounter one that requests asynchronous probing.
     */
    bool have_async;
};

static int __device_attach_driver(struct device_driver *drv, void *_data)
{
    struct device_attach_data *data = _data;
    struct device *dev = data->dev;
    bool async_allowed;
    int ret;

    ret = driver_match_device(drv, dev);
    if (ret == 0) {
        /* no match */
        return 0;
    } else if (ret == -EPROBE_DEFER) {
        pr_info("Device match requests probe deferral\n");
        dev->can_match = true;
        driver_deferred_probe_add(dev);
    } else if (ret < 0) {
        pr_info("Bus failed to match device: %d\n", ret);
        return ret;
    } /* ret > 0 means positive match */

#if 0
    async_allowed = driver_allows_async_probing(drv);

    if (async_allowed)
        data->have_async = true;

    if (data->check_async && async_allowed != data->want_async)
        return 0;
#endif

    /*
     * Ignore errors returned by ->probe so that the next driver can try
     * its luck.
     */
    ret = driver_probe_device(drv, dev);
    if (ret < 0)
        return ret;
    return ret == 0;
}

static int __device_attach(struct device *dev, bool allow_async)
{
    int ret = 0;

    device_lock(dev);
    if (dev->p->dead) {
        goto out_unlock;
    } else if (dev->driver) {
        if (device_is_bound(dev)) {
            ret = 1;
            goto out_unlock;
        }
        ret = device_bind_driver(dev);
        if (ret == 0)
            ret = 1;
        else {
            dev->driver = NULL;
            ret = 0;
        }
    } else {
        struct device_attach_data data = {
            .dev = dev,
            .check_async = allow_async,
            .want_async = false,
        };

#if 0
        if (dev->parent)
            pm_runtime_get_sync(dev->parent);
#endif

        ret = bus_for_each_drv(dev->bus, NULL, &data, __device_attach_driver);
        if (!ret && allow_async && data.have_async) {
            /*
             * If we could not find appropriate driver
             * synchronously and we are allowed to do
             * async probes and there are drivers that
             * want to probe asynchronously, we'll
             * try them.
             */
            panic("scheduling asynchronous probe\n");
            get_device(dev);
#if 0
            async_schedule_dev(__device_attach_async_helper, dev);
#endif
        } else {
#if 0
            pm_request_idle(dev);
#endif
        }

#if 0
        if (dev->parent)
            pm_runtime_put(dev->parent);
#endif
    }

 out_unlock:
    device_unlock(dev);
    return ret;
}

void device_initial_probe(struct device *dev)
{
    __device_attach(dev, true);
}
