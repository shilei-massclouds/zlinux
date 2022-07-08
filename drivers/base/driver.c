// SPDX-License-Identifier: GPL-2.0
/*
 * driver.c - centralized device driver management
 *
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 * Copyright (c) 2007 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2007 Novell Inc.
 */

#include <linux/device/driver.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include "base.h"

/**
 * driver_find - locate driver on a bus by its name.
 * @name: name of the driver.
 * @bus: bus to scan for the driver.
 *
 * Call kset_find_obj() to iterate over list of drivers on
 * a bus to find driver by name. Return driver if found.
 *
 * This routine provides no locking to prevent the driver it returns
 * from being unregistered or unloaded while the caller is using it.
 * The caller is responsible for preventing this.
 */
struct device_driver *driver_find(const char *name, struct bus_type *bus)
{
    struct kobject *k = kset_find_obj(bus->p->drivers_kset, name);
    struct driver_private *priv;

    if (k) {
        /* Drop reference added by kset_find_obj() */
        kobject_put(k);
        priv = to_driver(k);
        return priv->driver;
    }
    return NULL;
}
EXPORT_SYMBOL_GPL(driver_find);

/**
 * driver_register - register driver with bus
 * @drv: driver to register
 *
 * We pass off most of the work to the bus_add_driver() call,
 * since most of the things we have to do deal with the bus
 * structures.
 */
int driver_register(struct device_driver *drv)
{
    int ret;
    struct device_driver *other;

    if (!drv->bus->p) {
        pr_err("Driver '%s' was unable to register with bus_type '%s' "
               "because the bus was not initialized.\n",
               drv->name, drv->bus->name);
        return -EINVAL;
    }

    if ((drv->bus->probe && drv->probe) || (drv->bus->remove && drv->remove) ||
        (drv->bus->shutdown && drv->shutdown))
        pr_warn("Driver '%s' needs updating - please use bus_type methods\n",
                drv->name);

    other = driver_find(drv->name, drv->bus);
    if (other) {
        pr_err("Error: Driver '%s' is already registered, aborting...\n",
               drv->name);
        return -EBUSY;
    }

    ret = bus_add_driver(drv);
    if (ret)
        return ret;

#if 0
    ret = driver_add_groups(drv, drv->groups);
    if (ret) {
        bus_remove_driver(drv);
        return ret;
    }
    kobject_uevent(&drv->p->kobj, KOBJ_ADD);
#endif

    return ret;
}
EXPORT_SYMBOL_GPL(driver_register);

/**
 * driver_unregister - remove driver from system.
 * @drv: driver.
 *
 * Again, we pass off most of the work to the bus-level call.
 */
void driver_unregister(struct device_driver *drv)
{
    if (!drv || !drv->p) {
        WARN(1, "Unexpected driver unregister!\n");
        return;
    }
    panic("%s: END!\n", __func__);
#if 0
    driver_remove_groups(drv, drv->groups);
    bus_remove_driver(drv);
#endif
}
EXPORT_SYMBOL_GPL(driver_unregister);
