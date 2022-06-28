// SPDX-License-Identifier: GPL-2.0
/*
 * bus.c - bus driver management
 *
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 * Copyright (c) 2007 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2007 Novell Inc.
 */

#if 0
#include <linux/async.h>
#endif
#include <linux/device/bus.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>

#include "base.h"

static struct bus_type *bus_get(struct bus_type *bus)
{
    if (bus) {
        kset_get(&bus->p->subsys);
        return bus;
    }
    return NULL;
}

static void bus_put(struct bus_type *bus)
{
    if (bus)
        kset_put(&bus->p->subsys);
}

/**
 * bus_add_device - add device to bus
 * @dev: device being added
 *
 * - Add device's bus attributes.
 * - Create links to device's bus.
 * - Add the device to its bus's list of devices.
 */
int bus_add_device(struct device *dev)
{
    struct bus_type *bus = bus_get(dev->bus);
    int error = 0;

    if (bus) {
        pr_info("bus: '%s': add device %s\n", bus->name, dev_name(dev));
#if 0
        error = device_add_groups(dev, bus->dev_groups);
        if (error)
            goto out_put;
        error = sysfs_create_link(&bus->p->devices_kset->kobj,
                        &dev->kobj, dev_name(dev));
        if (error)
            goto out_groups;
        error = sysfs_create_link(&dev->kobj,
                &dev->bus->p->subsys.kobj, "subsystem");
        if (error)
            goto out_subsys;
#endif
        klist_add_tail(&dev->p->knode_bus, &bus->p->klist_devices);
    }
    return 0;

out_subsys:
    //sysfs_remove_link(&bus->p->devices_kset->kobj, dev_name(dev));
out_groups:
    //device_remove_groups(dev, bus->dev_groups);
out_put:
    panic("%s: ERR!\n", __func__);
    bus_put(dev->bus);
    return error;
}

/**
 * bus_register - register a driver-core subsystem
 * @bus: bus to register
 *
 * Once we have that, we register the bus with the kobject
 * infrastructure, then register the children subsystems it has:
 * the devices and drivers that belong to the subsystem.
 */
int bus_register(struct bus_type *bus)
{
    int retval;
    struct subsys_private *priv;

    priv = kzalloc(sizeof(struct subsys_private), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;

    priv->bus = bus;
    bus->p = priv;

    //BLOCKING_INIT_NOTIFIER_HEAD(&priv->bus_notifier);

    retval = kobject_set_name(&priv->subsys.kobj, "%s", bus->name);
    if (retval)
        goto out;

    pr_warn("bus: '%s': registered\n", bus->name);
    return 0;

bus_groups_fail:
    //remove_probe_files(bus);
bus_probe_files_fail:
    kset_unregister(bus->p->drivers_kset);
bus_drivers_fail:
    kset_unregister(bus->p->devices_kset);
bus_devices_fail:
    //bus_remove_file(bus, &bus_attr_uevent);
bus_uevent_fail:
    kset_unregister(&bus->p->subsys);
out:
    kfree(bus->p);
    bus->p = NULL;
    return retval;
}
EXPORT_SYMBOL_GPL(bus_register);
