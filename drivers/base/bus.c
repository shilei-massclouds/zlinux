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

/* /sys/devices/system */
static struct kset *system_kset;

static struct kset *bus_kset;

static const struct kset_uevent_ops bus_uevent_ops = {
    //.filter = bus_uevent_filter,
};

static void bus_release(struct kobject *kobj)
{
    struct subsys_private *priv = to_subsys_private(kobj);
    struct bus_type *bus = priv->bus;

    kfree(priv);
    bus->p = NULL;
}

static struct kobj_type bus_ktype = {
    //.sysfs_ops  = &bus_sysfs_ops,
    .release    = bus_release,
};

static void driver_release(struct kobject *kobj)
{
    struct driver_private *drv_priv = to_driver(kobj);

    pr_info("driver: '%s': %s\n", kobject_name(kobj), __func__);
    kfree(drv_priv);
}

static struct kobj_type driver_ktype = {
    //.sysfs_ops  = &driver_sysfs_ops,
    .release    = driver_release,
};

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

static void klist_devices_get(struct klist_node *n)
{
    struct device_private *dev_prv = to_device_private_bus(n);
    struct device *dev = dev_prv->device;

    get_device(dev);
}

static void klist_devices_put(struct klist_node *n)
{
    struct device_private *dev_prv = to_device_private_bus(n);
    struct device *dev = dev_prv->device;

    put_device(dev);
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

#if 0
    BLOCKING_INIT_NOTIFIER_HEAD(&priv->bus_notifier);
#endif

    retval = kobject_set_name(&priv->subsys.kobj, "%s", bus->name);
    if (retval)
        goto out;

    priv->subsys.kobj.kset = bus_kset;
    priv->subsys.kobj.ktype = &bus_ktype;
    priv->drivers_autoprobe = 1;

    retval = kset_register(&priv->subsys);
    if (retval)
        goto out;

#if 0
    retval = bus_create_file(bus, &bus_attr_uevent);
    if (retval)
        goto bus_uevent_fail;
#endif

    priv->devices_kset = kset_create_and_add("devices", NULL,
                                             &priv->subsys.kobj);
    if (!priv->devices_kset) {
        retval = -ENOMEM;
        goto bus_devices_fail;
    }

    priv->drivers_kset = kset_create_and_add("drivers", NULL,
                                             &priv->subsys.kobj);
    if (!priv->drivers_kset) {
        retval = -ENOMEM;
        goto bus_drivers_fail;
    }

    INIT_LIST_HEAD(&priv->interfaces);
    __mutex_init(&priv->mutex, "subsys mutex", NULL);
    klist_init(&priv->klist_devices, klist_devices_get, klist_devices_put);
    klist_init(&priv->klist_drivers, NULL, NULL);

#if 0
    retval = add_probe_files(bus);
    if (retval)
        goto bus_probe_files_fail;

    retval = bus_add_groups(bus, bus->bus_groups);
    if (retval)
        goto bus_groups_fail;
#endif

    pr_debug("bus: '%s': registered\n", bus->name);
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

/**
 * bus_add_driver - Add a driver to the bus.
 * @drv: driver.
 */
int bus_add_driver(struct device_driver *drv)
{
    struct bus_type *bus;
    struct driver_private *priv;
    int error = 0;

    bus = bus_get(drv->bus);
    if (!bus)
        return -EINVAL;

    pr_info("bus: '%s': add driver %s\n", bus->name, drv->name);

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        error = -ENOMEM;
        goto out_put_bus;
    }
    klist_init(&priv->klist_devices, NULL, NULL);
    priv->driver = drv;
    drv->p = priv;
    priv->kobj.kset = bus->p->drivers_kset;
    error = kobject_init_and_add(&priv->kobj, &driver_ktype, NULL,
                                 "%s", drv->name);
    if (error)
        goto out_unregister;

    klist_add_tail(&priv->knode_bus, &bus->p->klist_drivers);
    if (drv->bus->p->drivers_autoprobe) {
        error = driver_attach(drv);
        if (error)
            goto out_unregister;
    }
#if 0
    module_add_driver(drv->owner, drv);

    error = driver_create_file(drv, &driver_attr_uevent);
    if (error) {
        printk(KERN_ERR "%s: uevent attr (%s) failed\n",
               __func__, drv->name);
    }
    error = driver_add_groups(drv, bus->drv_groups);
    if (error) {
        /* How the hell do we get out of this pickle? Give up */
        printk(KERN_ERR "%s: driver_add_groups(%s) failed\n",
               __func__, drv->name);
    }

    if (!drv->suppress_bind_attrs) {
        error = add_bind_files(drv);
        if (error) {
            /* Ditto */
            printk(KERN_ERR "%s: add_bind_files(%s) failed\n",
                   __func__, drv->name);
        }
    }
#endif

    return 0;

 out_unregister:
    kobject_put(&priv->kobj);
    /* drv->p is freed in driver_release()  */
    drv->p = NULL;

 out_put_bus:
    bus_put(bus);
    return error;
}

static struct device *next_device(struct klist_iter *i)
{
    struct klist_node *n = klist_next(i);
    struct device *dev = NULL;
    struct device_private *dev_prv;

    if (n) {
        dev_prv = to_device_private_bus(n);
        dev = dev_prv->device;
    }
    return dev;
}

/**
 * bus_for_each_dev - device iterator.
 * @bus: bus type.
 * @start: device to start iterating from.
 * @data: data for the callback.
 * @fn: function to be called for each device.
 *
 * Iterate over @bus's list of devices, and call @fn for each,
 * passing it @data. If @start is not NULL, we use that device to
 * begin iterating from.
 *
 * We check the return of @fn each time. If it returns anything
 * other than 0, we break out and return that value.
 *
 * NOTE: The device that returns a non-zero value is not retained
 * in any way, nor is its refcount incremented. If the caller needs
 * to retain this data, it should do so, and increment the reference
 * count in the supplied callback.
 */
int bus_for_each_dev(struct bus_type *bus, struct device *start,
                     void *data, int (*fn)(struct device *, void *))
{
    struct klist_iter i;
    struct device *dev;
    int error = 0;

    if (!bus || !bus->p)
        return -EINVAL;

    klist_iter_init_node(&bus->p->klist_devices, &i,
                         (start ? &start->p->knode_bus : NULL));
    while (!error && (dev = next_device(&i)))
        error = fn(dev, data);
    klist_iter_exit(&i);
    return error;
}

/**
 * bus_unregister - remove a bus from the system
 * @bus: bus.
 *
 * Unregister the child subsystems and the bus itself.
 * Finally, we call bus_put() to release the refcount
 */
void bus_unregister(struct bus_type *bus)
{
    pr_debug("bus: '%s': unregistering\n", bus->name);
    if (bus->dev_root)
        device_unregister(bus->dev_root);
#if 0
    bus_remove_groups(bus, bus->bus_groups);
    remove_probe_files(bus);
#endif
    kset_unregister(bus->p->drivers_kset);
    kset_unregister(bus->p->devices_kset);
#if 0
    bus_remove_file(bus, &bus_attr_uevent);
#endif
    kset_unregister(&bus->p->subsys);
}
EXPORT_SYMBOL_GPL(bus_unregister);

/**
 * bus_probe_device - probe drivers for a new device
 * @dev: device to probe
 *
 * - Automatically probe for a driver if the bus allows it.
 */
void bus_probe_device(struct device *dev)
{
    struct bus_type *bus = dev->bus;
    struct subsys_interface *sif;

    if (!bus)
        return;

    if (bus->p->drivers_autoprobe)
        device_initial_probe(dev);

#if 0
    mutex_lock(&bus->p->mutex);
    list_for_each_entry(sif, &bus->p->interfaces, node)
        if (sif->add_dev)
            sif->add_dev(dev, sif);
    mutex_unlock(&bus->p->mutex);
#endif
}

int __init buses_init(void)
{
    bus_kset = kset_create_and_add("bus", &bus_uevent_ops, NULL);
    if (!bus_kset)
        return -ENOMEM;

    system_kset = kset_create_and_add("system", NULL, &devices_kset->kobj);
    if (!system_kset)
        return -ENOMEM;

    return 0;
}
